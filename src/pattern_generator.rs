use anyhow::Result;
use crate::ai::{client::AiClient, models::AiSettings};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

use crate::parser::Definition;
use crate::repo::RepoOps;
use crate::security_patterns::Language;

fn build_ai_client_for_patterns(api_base_url: Option<&str>, api_keys: &HashMap<String, String>) -> Result<AiClient> {
    let api_key = api_keys
        .get("openai")
        .or_else(|| api_keys.get("groq"))
        .or_else(|| api_keys.get("azure"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing api_key in config.api.api_keys"))?;
    let settings = AiSettings {
        api_key,
        base_url: api_base_url.map(|s| s.to_string()),
        model: String::new(),
        org_id: None,
        project_id: None,
        timeout_secs: 240,
        retries: 2,
    };
    Ok(AiClient::new(&settings))
}

fn filter_files_by_size(files: &[PathBuf], max_lines: usize) -> Result<Vec<PathBuf>> {
    let mut filtered_files = Vec::new();

    for file_path in files {
        match std::fs::read_to_string(file_path) {
            Ok(content) => {
                let line_count = content.lines().count();
                if line_count <= max_lines {
                    filtered_files.push(file_path.clone());
                }
            }
            Err(e) => {
                eprintln!("⚠️  ファイル読み込みエラー: {}: {}", file_path.display(), e);
                // Skip files that can't be read
                continue;
            }
        }
    }

    Ok(filtered_files)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PatternClassification {
    pub function_name: String,
    pub pattern_type: Option<String>,
    pub query_type: String, // "definition" or "reference"
    pub query: String,      // tree-sitter query instead of regex pattern
    pub description: String,
    pub reasoning: String,
    pub attack_vector: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PatternAnalysisResponse {
    patterns: Vec<PatternClassification>,
}

pub async fn generate_custom_patterns(
    root_dir: &Path,
    model: &str,
    api_base_url: Option<&str>,
    api_keys: &HashMap<String, String>,
) -> Result<()> {
    generate_custom_patterns_impl(root_dir, model, 4, api_base_url, api_keys).await
}

async fn generate_custom_patterns_impl(
    root_dir: &Path,
    model: &str,
    _max_parallel: usize,
    api_base_url: Option<&str>,
    api_keys: &HashMap<String, String>,
) -> Result<()> {
    println!(
        "📂 正在解析目录并提取 definitions: {}",
        root_dir.display()
    );

    let repo = RepoOps::new(root_dir.to_path_buf());
    let files = repo.get_files_to_analyze(None)?;

    println!("📁 检测到的文件数: {}", files.len());

    let max_lines = 1000;
    let filtered_files = filter_files_by_size(&files, max_lines)?;
    let skipped_count = files.len() - filtered_files.len();

    if skipped_count > 0 {
        println!(
            "⚠️  已跳过超过{}行的大文件共{}个",
            max_lines, skipped_count
        );
    }

    println!("📁 待分析文件数: {}", filtered_files.len());

    let mut all_definitions: Vec<(Definition, Language)> = Vec::new();
    let mut all_references: Vec<(Definition, Language)> = Vec::new();
    let mut languages_found = HashMap::new();
    let mut seen_names = std::collections::HashSet::new();

    for file_path in &filtered_files {
        let mut parser = crate::parser::CodeParser::new()?;
        if let Err(e) = parser.add_file(file_path) {
            eprintln!(
                "⚠️  添加文件到解析器失败: {}: {}",
                file_path.display(),
                e
            );
            continue;
        }

        match parser.build_context_from_file(file_path) {
            Ok(context) => {
                let filename = file_path.to_string_lossy();
                let content = std::fs::read_to_string(file_path).unwrap_or_default();
                let language =
                    crate::file_classifier::FileClassifier::classify(&filename, &content);
                languages_found.insert(language, true);

                println!(
                    "📄 {} (言語: {:?}) から {}個のdefinitions、{}個のreferencesを検出",
                    file_path.display(),
                    language,
                    context.definitions.len(),
                    context.references.len()
                );
                // if !context.definitions.is_empty() {
                //     for def in &context.definitions {
                //         print!("{},", def.name);
                //     }
                //     println!();
                // }
                // if !context.references.is_empty() {
                //     for ref_def in &context.references {
                //         print!("{},", ref_def.name);
                //     }
                //     println!();
                // }
                for def in context.definitions {
                    seen_names.insert(def.name.clone());
                    all_definitions.push((def, language));
                }
                for ref_def in context.references {
                    all_references.push((ref_def, language));
                }
            }
            Err(e) => {
                eprintln!("⚠️  收集上下文失败: {}: {}", file_path.display(), e);
                continue;
            }
        }
    }

        println!(
            "🔍 共提取 {} 个 definitions，{} 个 references",
            all_definitions.len(),
            all_references.len()
        );

    for (language, _) in languages_found {
        // Combine definitions and references for this language
        let lang_definitions: Vec<_> = all_definitions
            .iter()
            .filter(|(_, lang)| *lang == language)
            .map(|(def, _)| def)
            .collect();

        let lang_references: Vec<_> = all_references
            .iter()
            .filter(|(_, lang)| *lang == language)
            .map(|(def, _)| def)
            .collect();

        let total_items = lang_definitions.len() + lang_references.len();
        if total_items == 0 {
            continue;
        }

        println!(
            "🧠 正在分析 {:?} 语言中的 {} 个 definitions、{} 个 references...",
            language,
            lang_definitions.len(),
            lang_references.len()
        );

        // Process definitions and references separately to maintain their distinctions
        let mut definition_patterns = Vec::new();
        let mut reference_patterns = Vec::new();

        if !lang_definitions.is_empty() {
            definition_patterns = analyze_definitions_for_security_patterns(
                model,
                &lang_definitions,
                language,
                api_base_url,
                api_keys,
            )
            .await?;
        }

        if !lang_references.is_empty() {
            reference_patterns = analyze_references_for_security_patterns(
                model,
                &lang_references,
                language,
                api_base_url,
                api_keys,
            )
            .await?;
        }

        // Combine all patterns
        let mut all_patterns = definition_patterns;
        all_patterns.extend(reference_patterns);

        // Deduplicate patterns based on function name
        let mut unique_patterns = Vec::new();
        let mut seen_functions = std::collections::HashSet::new();

        for pattern in all_patterns {
            if seen_functions.insert(pattern.function_name.clone()) {
                unique_patterns.push(pattern);
            }
        }

        if !unique_patterns.is_empty() {
            write_patterns_to_file(root_dir, language, &unique_patterns)?;
            println!(
                "✅ 已为 {:?} 语言生成 {} 个模式",
                language,
                unique_patterns.len()
            );
        } else {
            println!(
                "ℹ️  在 {:?} 语言中未检测到安全模式",
                language
            );
        }
    }

    println!("🎉 自定义模式生成已完成");
    Ok(())
}

pub async fn analyze_definitions_for_security_patterns<'a>(
    model: &str,
    definitions: &'a [&crate::parser::Definition],
    language: Language,
    api_base_url: Option<&str>,
    api_keys: &HashMap<String, String>,
) -> Result<Vec<PatternClassification>> {
    analyze_all_definitions_at_once(model, definitions, language, api_base_url, api_keys).await
}

pub async fn analyze_references_for_security_patterns<'a>(
    model: &str,
    references: &'a [&crate::parser::Definition],
    language: Language,
    api_base_url: Option<&str>,
    api_keys: &HashMap<String, String>,
) -> Result<Vec<PatternClassification>> {
    analyze_all_references_at_once(model, references, language, api_base_url, api_keys).await
}

async fn analyze_all_definitions_at_once(
    model: &str,
    definitions: &[&crate::parser::Definition],
    language: Language,
    api_base_url: Option<&str>,
    api_keys: &HashMap<String, String>,
) -> Result<Vec<PatternClassification>> {
    if definitions.is_empty() {
        return Ok(Vec::new());
    }

    // Create context for all definitions
    let mut definitions_context = String::new();
    for (idx, def) in definitions.iter().enumerate() {
        definitions_context.push_str(&format!(
            "Definition {}: {}\nCode:\n{}\n\n",
            idx + 1,
            def.name,
            def.source
        ));
    }

    let prompt = format!(
        r#"Analyze these function definitions from a {:?} codebase and determine which represent security patterns.

{}

For each function, determine if it should be classified as:
- "principals": Sources that act as data entry points and should be treated as tainted/untrusted
- "actions": Functions that perform validation, sanitization, authorization, or security operations  
- "resources": Functions that access, modify, or perform operations on files, databases, networks, or system resources
- "none": Not a security pattern

Generate tree-sitter queries instead of regex patterns. Use the following format:

IMPORTANT: For definition patterns, add @function capture to the entire function_definition.
For reference patterns, add @call capture to the entire call_expression or @attribute capture to the entire attribute access.
This ensures we capture the complete context, not just the identifier names.

Return a JSON object with this structure:

{{
  "patterns": [
    {{
      "classification": "principals|actions|resources|none",
      "function_name": "function_name",
      "query_type": "definition",
      "query": "(function_definition name: (identifier) @name (#eq? @name \"function_name\")) @function",
      "description": "Brief description of what this pattern detects",
      "reasoning": "Why this function fits this classification",
      "attack_vector": ["T1234", "T5678"]
    }}
  ]
}}

All fields are required for each object. Use proper tree-sitter query syntax for the {:?} language."#,
        language, definitions_context, language
    );

    let response_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "patterns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "classification": {"type": "string", "enum": ["principals", "actions", "resources", "none"]},
                        "function_name": {"type": "string"},
                        "query_type": {"type": "string", "enum": ["definition", "reference"]},
                        "query": {"type": "string"},
                        "description": {"type": "string"},
                        "reasoning": {"type": "string"},
                        "attack_vector": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["classification", "function_name", "query_type", "query", "description", "reasoning", "attack_vector"]
                }
            }
        },
        "required": ["patterns"]
    });

    let client = build_ai_client_for_patterns(api_base_url, api_keys)?;
    let system_prompt = "You are a security pattern analyzer. Reply with exactly one JSON object containing a 'patterns' array with analysis for all functions. Be conservative - only classify as security patterns if clearly relevant.";
    let content = client.chat_json_custom(model, system_prompt, &prompt, response_schema).await?;

    #[derive(Deserialize)]
    struct BatchAnalysisResponse {
        patterns: Vec<PatternResponse>,
    }

    #[derive(Deserialize)]
    struct PatternResponse {
        classification: String,
        function_name: String,
        query_type: String,
        query: String,
        description: String,
        reasoning: String,
        attack_vector: Vec<String>,
    }

    let response: BatchAnalysisResponse = serde_json::from_str(&content).map_err(|e| {
        anyhow::anyhow!("Failed to parse LLM response: {}. Content: {}", e, content)
    })?;

    let mut patterns = Vec::new();
    let mut security_pattern_count = 0;

    for pattern_resp in response.patterns {
        if pattern_resp.classification != "none" {
            patterns.push(PatternClassification {
                function_name: pattern_resp.function_name,
                pattern_type: Some(pattern_resp.classification),
                query_type: pattern_resp.query_type,
                query: pattern_resp.query,
                description: pattern_resp.description,
                reasoning: pattern_resp.reasoning,
                attack_vector: pattern_resp.attack_vector,
            });
            security_pattern_count += 1;
        }
    }

        println!(
            "✅ 完成: 共分析 {} 项，检测到安全模式 {} 项",
            definitions.len(),
            security_pattern_count
        );

    Ok(patterns)
}

async fn analyze_all_references_at_once(
    model: &str,
    references: &[&crate::parser::Definition],
    language: Language,
    api_base_url: Option<&str>,
    api_keys: &HashMap<String, String>,
) -> Result<Vec<PatternClassification>> {
    if references.is_empty() {
        return Ok(Vec::new());
    }

    // Create context for all references
    let mut references_context = String::new();
    for (idx, ref_def) in references.iter().enumerate() {
        references_context.push_str(&format!(
            "Reference {}: {}\nCode:\n{}\n\n",
            idx + 1,
            ref_def.name,
            ref_def.source
        ));
    }

    let prompt = format!(
        r#"Analyze these function references/calls from a {:?} codebase and determine which represent calls to security-sensitive functions.

{}

For each function reference, determine if it should be classified as:
- "principals": Functions that return or provide untrusted data that attackers can control. This includes:
  * User input functions (request.params, request.body, request.query)
  * External data sources (API responses, file readers, socket data)
  * Network/communication inputs (HTTP requests, message queues)
  * Functions that retrieve attacker-controlled data
  * Any function that introduces data from outside the application's control boundary
  
- "actions": Functions that perform security processing (validation, sanitization, authorization). This includes:
  * Input validation functions (validators, sanitizers)
  * Authentication/authorization functions (login checks, permission checks)
  * Cryptographic functions (encryption, hashing, signing)
  * Security-focused data transformation functions
  
- "resources": Functions that operate on attack targets (files, databases, system commands, DOM). This includes:
  * File system operations (readFile, writeFile, deleteFile)
  * Database operations (query, insert, update, delete)
  * System command execution (exec, spawn, system)
  * DOM manipulation (innerHTML, setAttribute, createElement)
  * Network operations (HTTP requests, socket connections)
  
- "none": Not a security-relevant call

## Classification Examples:

**Principal Examples:**
- `request.params.get('user_id')` - returns untrusted user input
- `os.environ.get('USER_INPUT')` - if environment variable contains user data
- `json.loads(request.body)` - parses untrusted JSON data

**Action Examples:**
- `validate_email(email)` - validates email format
- `bcrypt.hash(password)` - hashes password securely
- `escape_html(content)` - sanitizes HTML content

**Resource Examples:**
- `fs.readFileSync(filepath)` - reads file from filesystem
- `db.query(sql, params)` - executes database query
- `document.getElementById('output').innerHTML` - modifies DOM
- `os.system(command)` - executes system command

Focus especially on identifying principals that represent sources in source-sink analysis patterns. These are the starting points where untrusted data enters the application.

Generate tree-sitter queries instead of regex patterns. Use the following format:

IMPORTANT: For definition patterns, add @function capture to the entire function_definition.
For reference patterns, add @call capture to the entire call_expression or @attribute capture to the entire attribute access.
This ensures we capture the complete context, not just the identifier names.

Return a JSON object with this structure:

{{
  "patterns": [
    {{
      "classification": "principals|actions|resources|none",
      "function_name": "function_name",
      "query_type": "reference",
      "query": "(call_expression function: (identifier) @name (#eq? @name \"function_name\")) @call",
      "description": "Brief description of what this pattern detects",
      "reasoning": "Why this function call fits this classification",
      "attack_vector": ["T1234", "T5678"]
    }}
  ]
}}

All fields are required for each object. Use proper tree-sitter query syntax for the {:?} language."#,
        language, references_context, language
    );

    let response_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "patterns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "classification": {"type": "string", "enum": ["principals", "actions", "resources", "none"]},
                        "function_name": {"type": "string"},
                        "query_type": {"type": "string", "enum": ["definition", "reference"]},
                        "query": {"type": "string"},
                        "description": {"type": "string"},
                        "reasoning": {"type": "string"},
                        "attack_vector": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["classification", "function_name", "query_type", "query", "description", "reasoning", "attack_vector"]
                }
            }
        },
        "required": ["patterns"]
    });

    let client = build_ai_client_for_patterns(api_base_url, api_keys)?;
    let system_prompt = "You are a security pattern analyzer for function references. Reply with exactly one JSON object containing a 'patterns' array with analysis for all function calls. Focus on calls to security-sensitive functions.";
    let content = client.chat_json_custom(model, system_prompt, &prompt, response_schema).await?;

    #[derive(Deserialize)]
    struct BatchAnalysisResponse {
        patterns: Vec<PatternResponse>,
    }

    #[derive(Deserialize)]
    struct PatternResponse {
        classification: String,
        function_name: String,
        query_type: String,
        query: String,
        description: String,
        reasoning: String,
        attack_vector: Vec<String>,
    }

    let response: BatchAnalysisResponse = serde_json::from_str(&content).map_err(|e| {
        anyhow::anyhow!("Failed to parse LLM response: {}. Content: {}", e, content)
    })?;

    let mut patterns = Vec::new();
    let mut security_pattern_count = 0;

    for pattern_resp in response.patterns {
        if pattern_resp.classification != "none" {
            patterns.push(PatternClassification {
                function_name: pattern_resp.function_name,
                pattern_type: Some(pattern_resp.classification),
                query_type: pattern_resp.query_type,
                query: pattern_resp.query,
                description: pattern_resp.description,
                reasoning: pattern_resp.reasoning,
                attack_vector: pattern_resp.attack_vector,
            });
            security_pattern_count += 1;
        }
    }

    println!(
        "✅ 完成: 共分析 {} 个引用，检测到安全模式 {} 项",
        references.len(),
        security_pattern_count
    );

    Ok(patterns)
}

pub fn write_patterns_to_file(
    root_dir: &Path,
    language: Language,
    patterns: &[PatternClassification],
) -> Result<()> {
    let mut vuln_patterns_path = root_dir.to_path_buf();
    vuln_patterns_path.push("vuln-patterns.yml");

    let lang_name = match language {
        Language::Python => "Python",
        Language::JavaScript => "JavaScript",
        Language::TypeScript => "TypeScript",
        Language::Rust => "Rust",
        Language::Java => "Java",
        Language::Go => "Go",
        Language::Ruby => "Ruby",
        Language::C => "C",
        Language::Cpp => "Cpp",
        Language::Terraform => "Terraform",
        Language::CloudFormation => "CloudFormation",
        Language::Kubernetes => "Kubernetes",
        Language::Yaml => "YAML",
        Language::Bash => "Bash",
        Language::Shell => "Shell",
        Language::Php => "Php",
        Language::Other => return Ok(()),
    };

    let mut principals = Vec::new();
    let mut actions = Vec::new();
    let mut resources = Vec::new();

    for pattern in patterns {
        match pattern.pattern_type.as_deref() {
            Some("principals") => principals.push(pattern),
            Some("actions") => actions.push(pattern),
            Some("resources") => resources.push(pattern),
            _ => {}
        }
    }

    let mut yaml_content = format!("{}:\n", lang_name);

    if !principals.is_empty() {
        yaml_content.push_str("  principals:\n");
        for pattern in principals {
            yaml_content.push_str(&format!(
                "    - {}: |\n",
                pattern.query_type
            ));
            // Add indented query
            for line in pattern.query.lines() {
                yaml_content.push_str(&format!("        {}\n", line));
            }
            yaml_content.push_str(&format!(
                "      description: \"{}\"\n",
                pattern.description
            ));
            yaml_content.push_str("      attack_vector:\n");
            if !pattern.attack_vector.is_empty() {
                for technique in &pattern.attack_vector {
                    yaml_content.push_str(&format!("        - \"{}\"\n", technique));
                }
            } else {
                yaml_content.push_str("        []\n");
            }
        }
    }

    if !actions.is_empty() {
        yaml_content.push_str("  actions:\n");
        for pattern in actions {
            yaml_content.push_str(&format!(
                "    - {}: |\n",
                pattern.query_type
            ));
            // Add indented query
            for line in pattern.query.lines() {
                yaml_content.push_str(&format!("        {}\n", line));
            }
            yaml_content.push_str(&format!(
                "      description: \"{}\"\n",
                pattern.description
            ));
            yaml_content.push_str("      attack_vector:\n");
            if !pattern.attack_vector.is_empty() {
                for technique in &pattern.attack_vector {
                    yaml_content.push_str(&format!("        - \"{}\"\n", technique));
                }
            } else {
                yaml_content.push_str("        []\n");
            }
        }
    }

    if !resources.is_empty() {
        yaml_content.push_str("  resources:\n");
        for pattern in resources {
            yaml_content.push_str(&format!(
                "    - {}: |\n",
                pattern.query_type
            ));
            // Add indented query
            for line in pattern.query.lines() {
                yaml_content.push_str(&format!("        {}\n", line));
            }
            yaml_content.push_str(&format!(
                "      description: \"{}\"\n",
                pattern.description
            ));
            yaml_content.push_str("      attack_vector:\n");
            if !pattern.attack_vector.is_empty() {
                for technique in &pattern.attack_vector {
                    yaml_content.push_str(&format!("        - \"{}\"\n", technique));
                }
            } else {
                yaml_content.push_str("        []\n");
            }
        }
    }

    if vuln_patterns_path.exists() {
        let existing_content = std::fs::read_to_string(&vuln_patterns_path)?;
        let updated_content = format!("{}\n{}", existing_content, yaml_content);
        std::fs::write(&vuln_patterns_path, updated_content)?;
    } else {
        std::fs::write(&vuln_patterns_path, yaml_content)?;
    }

    println!(
        "📝 已写入模式文件: {}",
        vuln_patterns_path.display()
    );
    Ok(())
}
