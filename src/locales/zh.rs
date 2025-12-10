use std::collections::HashMap;

pub fn get_messages() -> HashMap<&'static str, &'static str> {
    let mut messages = HashMap::new();

    messages.insert("error_clone_failed", "删除克隆目标目录失败");
    messages.insert("cloning_repo", "正在克隆 GitHub 仓库");
    messages.insert("analysis_target", "分析目标");
    messages.insert("context_collection_failed", "收集上下文失败");
    messages.insert("analyzing_file", "正在分析文件");
    messages.insert("analysis_completed", "分析完成");
    messages.insert("error_directory_creation", "创建目录失败");
    messages.insert("error_no_write_permission", "没有写入权限");
    messages.insert("error_test_file_deletion", "删除测试文件失败");
    messages.insert("error_no_file_creation_permission", "没有文件创建权限");
    messages.insert("error_output_dir_check", "❌ 输出目录检查失败");
    messages.insert("relevant_files_detected", "已检测到相关源文件");
    messages.insert("security_pattern_files_detected", "已检测到安全模式匹配文件");
    messages.insert("parse_add_failed", "添加文件到解析器失败");
    messages.insert("analysis_failed", "分析失败");
    messages.insert("markdown_report_output_failed", "输出 Markdown 报告失败");
    messages.insert("markdown_report_output", "已输出 Markdown 报告");
    messages.insert("summary_report_output_failed", "输出汇总报告失败");
    messages.insert("summary_report_output", "已输出汇总报告");
    messages.insert("summary_report_needs_output_dir", "输出汇总报告需要 --output-dir 选项");
    messages.insert("sarif_report_output_failed", "输出 SARIF 报告失败");
    messages.insert("sarif_report_output", "已输出 SARIF 报告");
    messages.insert("sarif_output_failed", "输出 SARIF 失败");
    messages.insert("github_repo_clone_failed", "克隆 GitHub 仓库失败");
    messages.insert("custom_pattern_generation_start", "开始自定义模式生成");
    messages.insert("pattern_generation_completed", "模式生成完成");

    messages
}

pub const SYS_PROMPT_TEMPLATE: &str = r#"
作为安全研究员，请分析代码中的漏洞，重点关注：
- 输入校验与清理
- 身份验证与授权
- 数据处理与泄露
- 命令注入可能性
- 路径遍历漏洞
- 计时攻击与竞争条件
- 其他关键安全模式
"#;

pub const INITIAL_ANALYSIS_PROMPT_TEMPLATE: &str = r#"
基于 PAR（Principal-Action-Resource）模型，分析给定代码（函数定义或函数调用），并判定其所属类别：

Principal（不可信数据源）：提供攻击者可控数据的函数
Action（安全处理）：执行校验、清理、认证/授权等安全处理的函数
Resource（攻击目标）：操作文件系统、数据库、系统命令、DOM、网络等资源的函数

重要：对于函数调用，请根据被调用函数的性质进行分类。
"#;

pub const ANALYSIS_APPROACH_TEMPLATE: &str = r#"
PAR 模型分析步骤：
1. 识别不可信数据源（Principal）
2. 识别影响 CIA 的危险操作（Resource）
3. 评估从 Principal 到 Resource 路径上的安全处理（Action）
4. 检测策略违规（未经适当 Action 直接访问 Resource）
5. 在全局上下文中评估 PAR 关系的合理性
"#;

pub const GUIDELINES_TEMPLATE: &str = r#"
PAR 安全策略评估指南：
1. Principal 评估：识别不可信数据源及其风险
2. Resource 评估：评估影响 CIA 的操作风险
3. Action 评估：评估防护措施的实现质量
4. 策略违规：识别危险 Principal 未经适当 Action 直接访问 Resource 的情况
5. 上下文：基于全局代码上下文判断 PAR 关系合理性
"#;

pub const EVALUATOR_PROMPT_TEMPLATE: &str = r#"你是安全专家，负责评估漏洞分析报告。
请从漏洞识别准确性、误报、分析质量与验证代码质量等方面进行评价。

待评估报告：
{report}
"#;

pub const RESPONSE_LANGUAGE_INSTRUCTION: &str = "请使用中文进行回应";

