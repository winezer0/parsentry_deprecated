use parsentry::locales::Language;
use parsentry::locales::*;
use parsentry::prompts::vuln_specific;
use parsentry::response::VulnType;

#[test]
fn test_sys_prompt_template() {
    let template = get_sys_prompt_template(&Language::Chinese);
    assert!(!template.is_empty());
    assert!(template.contains("安全研究员") || template.contains("安全研究者"));
    assert!(template.contains("漏洞") || template.contains("脆弱性"));
    assert!(template.contains("输入校验") || template.contains("清理"));
    assert!(template.contains("身份验证") || template.contains("授权"));
}

#[test]
fn test_initial_analysis_prompt_template() {
    let template = get_initial_analysis_prompt_template(&Language::Chinese);
    assert!(!template.is_empty());
    assert!(template.contains("PAR"));
    assert!(template.contains("Principal"));
    assert!(template.contains("Action"));
    assert!(template.contains("Resource"));
}

#[test]
fn test_analysis_approach_template() {
    let template = get_analysis_approach_template(&Language::Chinese);
    assert!(!template.is_empty());
    assert!(template.contains("PAR 模型") || template.contains("PAR"));
    assert!(template.contains("Principal识别") || template.contains("Principal"));
    assert!(template.contains("Resource识别") || template.contains("Resource"));
    assert!(template.contains("Action评估") || template.contains("Action"));
    assert!(template.contains("策略违规") || template.contains("Policy"));
}

#[test]
fn test_guidelines_template() {
    let template = get_guidelines_template(&Language::Chinese);
    assert!(!template.is_empty());
    assert!(template.contains("PAR"));
    assert!(template.contains("Principal评估") || template.contains("Principal"));
    assert!(template.contains("Resource评估") || template.contains("Resource"));
    assert!(template.contains("Action评估") || template.contains("Action"));
    assert!(template.len() > 20);
}

#[test]
fn test_prompt_templates_are_non_empty() {
    let language = Language::Chinese;
    let templates = [
        get_sys_prompt_template(&language),
        get_initial_analysis_prompt_template(&language),
        get_analysis_approach_template(&language),
        get_guidelines_template(&language),
    ];

    for template in templates {
        assert!(!template.is_empty());
        assert!(template.len() > 10); // Reasonable minimum length
    }
}

#[test]
fn test_prompt_templates_contain_analysis_keywords() {
    let analysis_keywords = ["分析", "漏洞", "安全", "代码"];
    let language = Language::Chinese;

    let templates = [
        get_sys_prompt_template(&language),
        get_initial_analysis_prompt_template(&language),
        get_analysis_approach_template(&language),
        get_guidelines_template(&language),
    ];

    for template in templates {
        let contains_analysis_keywords = analysis_keywords
            .iter()
            .any(|keyword| template.contains(keyword));
        assert!(
            contains_analysis_keywords,
            "Template should contain analysis keywords"
        );
    }
}

#[test]
fn test_vuln_specific_module_exists() {
    // Test that the vuln_specific module can be accessed
    // This verifies the module structure is correct
    let vuln_info_map = vuln_specific::get_vuln_specific_info();
    assert!(!vuln_info_map.is_empty());
}

#[test]
fn test_vuln_info_map_contains_common_types() {
    let vuln_info_map = vuln_specific::get_vuln_specific_info();

    // Test that common vulnerability types are present
    let common_types = [VulnType::RCE, VulnType::SQLI, VulnType::XSS, VulnType::LFI];

    for vuln_type in common_types {
        assert!(
            vuln_info_map.contains_key(&vuln_type),
            "Should contain vulnerability type: {:?}",
            vuln_type
        );
    }
}

#[test]
fn test_vuln_info_structure() {
    let vuln_info_map = vuln_specific::get_vuln_specific_info();

    for (vuln_type, vuln_info) in &vuln_info_map {
        // Each vulnerability type should have non-empty prompt
        assert!(
            !vuln_info.prompt.is_empty(),
            "Prompt should not be empty for {:?}",
            vuln_type
        );

        // Prompt should be reasonably long
        assert!(
            vuln_info.prompt.len() > 20,
            "Prompt should be substantial for {:?}",
            vuln_type
        );

        // Bypasses can be empty but if present should be non-empty strings
        for bypass in &vuln_info.bypasses {
            assert!(
                !bypass.is_empty(),
                "Bypass strings should not be empty for {:?}",
                vuln_type
            );
        }
    }
}

#[test]
fn test_rce_specific_prompt() {
    let vuln_info_map = vuln_specific::get_vuln_specific_info();
    let rce_info = vuln_info_map.get(&VulnType::RCE);

    assert!(rce_info.is_some());
    let rce_info = rce_info.unwrap();

    // RCE prompt should contain relevant keywords (English or Japanese)
    assert!(
        rce_info.prompt.contains("Remote Code Execution")
            || rce_info.prompt.contains("Code Execution")
            || rce_info.prompt.contains("命令")
            || rce_info.prompt.contains("执行")
    );
    assert!(!rce_info.prompt.is_empty());
}

#[test]
fn test_sqli_specific_prompt() {
    let vuln_info_map = vuln_specific::get_vuln_specific_info();
    let sqli_info = vuln_info_map.get(&VulnType::SQLI);

    assert!(sqli_info.is_some());
    let sqli_info = sqli_info.unwrap();

    // SQL injection prompt should contain relevant keywords
    assert!(
        sqli_info.prompt.contains("SQL")
            || sqli_info.prompt.contains("数据库")
            || sqli_info.prompt.contains("查询")
    );
    assert!(!sqli_info.prompt.is_empty());
}

#[test]
fn test_xss_specific_prompt() {
    let vuln_info_map = vuln_specific::get_vuln_specific_info();
    let xss_info = vuln_info_map.get(&VulnType::XSS);

    assert!(xss_info.is_some());
    let xss_info = xss_info.unwrap();

    // XSS prompt should contain relevant keywords (English or Japanese)
    assert!(
        xss_info.prompt.contains("XSS")
            || xss_info.prompt.contains("脚本")
            || xss_info.prompt.contains("HTML")
            || xss_info.prompt.contains("Cross-Site Scripting")
    );
    assert!(!xss_info.prompt.is_empty());
}

#[test]
fn test_lfi_specific_prompt() {
    let vuln_info_map = vuln_specific::get_vuln_specific_info();
    let lfi_info = vuln_info_map.get(&VulnType::LFI);

    assert!(lfi_info.is_some());
    let lfi_info = lfi_info.unwrap();

    // LFI prompt should contain relevant keywords (English or Japanese)
    assert!(
        lfi_info.prompt.contains("Local File Inclusion")
            || lfi_info.prompt.contains("File")
            || lfi_info.prompt.contains("文件")
            || lfi_info.prompt.contains("路径")
            || lfi_info.prompt.contains("包含")
    );
    assert!(!lfi_info.prompt.is_empty());
}

#[test]
fn test_prompt_templates_formatting() {
    let language = Language::Chinese;
    let templates = [
        get_sys_prompt_template(&language),
        get_initial_analysis_prompt_template(&language),
        get_analysis_approach_template(&language),
        get_guidelines_template(&language),
    ];

    for template in templates {
        // Templates should contain meaningful content (allow leading/trailing whitespace)
        assert!(!template.trim().is_empty());

        // Templates should contain proper line breaks
        assert!(template.contains('\n'));
    }
}

#[test]
fn test_evaluator_prompt_template() {
    let template = get_evaluator_prompt_template(&Language::Chinese);

    assert!(!template.is_empty());
    // The evaluator prompt should be for evaluation purposes
    assert!(template.len() > 50); // Should be substantial
}
