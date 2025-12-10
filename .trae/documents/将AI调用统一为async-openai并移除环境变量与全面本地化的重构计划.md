## 范围与目标
- 限定：不改动 tree-sitter 相关目录与生成物；重构其余项目代码、测试与文档内运行时代码路径。
- 目标：
  - 统一使用 `async-openai` 实现所有 AI 接口调用，兼容 OpenAI API 语法以支持同规范供应商。
  - 彻底移除运行时代码中的环境变量使用，迁移到配置文件读取（API Key、Base URL、Org/Project、GitHub Token 等）。
  - 全面中文本地化（代码与注释），保留并增强中英双语输出与输入识别，自动选择语言偏好。
  - 完整的请求/响应流程：参数校验、错误与重试、超时控制、结构化 JSON 解析。
  - 构建与测试通过，并清理无用文件与过时资源。

## 依赖与配置
- Cargo.toml：
  - 添加 `async-openai`，启用 `responses`、`chat-completion`、`byot` 所需特性（最小化启用集）。
  - 保留现有 `tokio`、`serde`、`reqwest` 等依赖，移除 `genai` 相关依赖。
- 新增配置文件：`config/parsentry.toml`
  - `ai.api_key`、`ai.base_url`、`ai.model`、`ai.org_id`、`ai.project_id`（可选）
  - `ai.provider`（例如 `openai`、`groq`、`azure-openai`，用于路径/headers 差异化）
  - `github.token`（替代 `GITHUB_TOKEN`）
- 加载策略：应用启动读取一次并缓存；无配置时报错并提示创建模板。

## AI 客户端统一封装
- 新增模块：`src/ai/{client.rs, types.rs, errors.rs}`（每文件≤300行）
  - `ClientFactory`：接受 `Config`，构造 `async_openai::Client`，根据 `provider` 设置 `base_url`、headers 与模型字符串。
  - `RequestValidator`：校验必填项（`api_key`, `model`, `messages` 非空；长度与大小限制）。
  - `Executor`：
    - 首选 `Responses API`，当需要兼容旧模型或供应商时回退 `Chat Completions`。
    - 支持 BYOT：可使用 `serde_json::Value` 输入输出，便于 JSON Schema 约束与宽松字段扩展。
    - 超时：外层 `tokio::time::timeout`（默认 240s，可在 `config` 覆写）。
    - 重试：对 429/5xx 进行指数回退重试（与库内退避互补，最大次数可配置）。
  - `JsonSchema`：将原 `JsonSpec` 迁移为 `Responses API` 的 `json_schema`，保证严格 JSON 返回并解析。

## 替换现有 AI 调用路径
- `src/analyzer.rs`：
  - 移除 `genai` 与自定义 `ServiceTargetResolver`；改用统一 `ai::client` 与 `Executor`。
  - 保留现有：系统/用户提示构造、JSON 严格模式、超时、重试与 `sanitize/normalize_confidence_score` 流程。
  - 修复现存文案不一致（240s vs 180s），统一为配置值。
- `src/pattern_generator.rs`：
  - 同步迁移至统一客户端；生成提示、执行与解析均统一。
- 兼容不同供应商：
  - `provider=openai`：标准路径；
  - `provider=groq`：`base_url=https://api.groq.com/openai/v1`，不额外追加非规范路径；
  - `provider=azure-openai`：支持基于 `base_url` 与必要 headers；仅限与 OpenAI 规范一致端点。

## 环境变量移除与替代
- 删除/替换：
  - `OPENAI_API_KEY` → `config.ai.api_key`
  - `PARSENTRY_DISABLE_V1_PATH` → 通过 `provider` 与 `base_url` 显式配置控制路径行为。
  - `GITHUB_TOKEN`（`src/repo.rs`）→ `config.github.token`，用于凭证回调。
- `src/main.rs`：移除 `dotenvy::dotenv` 加载逻辑，改为 `ConfigLoader::load()`；保留 `env_logger` 初始化。
- 测试：不再从环境检测跳过；改为若无 `config/parsentry.toml` 或缺关键项则 `#[ignore]` 或条件执行并打印提示。
- 构建脚本：保留 `build.rs` 的编译期环境（`CARGO_MANIFEST_DIR` 等），不做改动（非运行时）。

## 本地化与双语支持
- 新增：`src/locales/{zh.rs, en.rs}` 与统一路由 `src/locales/mod.rs`，移除 `ja.rs`。
  - 将所有硬编码日文输出/模板迁移为键值（如 `msg.repo_clone_start`、`report.title_vuln_types`），在 `zh/en` 中分别定义。
  - 自动语言识别：
    - CLI 参数：`--lang auto|zh|en`（默认 `auto`）。
    - 输入检测：若用户输入包含大量中文字符则选 `zh`，否则选 `en`；可在 `config.ui.language_preference` 覆写。
  - 输出与日志：根据当前语言渲染；命令与参数解析同时接受中英关键字别名。
- 注释：统一改为中文；常量与代码标识保持英文；报告内容支持双语模板切换。

## 请求/响应流程保证
- 参数校验：模型名、消息长度、是否为空；非法字符与过长输入截断或报错。
- 超时控制：统一外层 `timeout`；记录耗时与原因。
- 错误处理：
  - 分类：超时、网络、认证、配额、供应商兼容性；
  - 重试策略：指数回退、上限可配置；
  - 结构化错误：使用 `thiserror` 定义业务错误并在 CLI 层友好输出（中英双语）。
- 响应解析：严格 JSON；`sanitize()`、`normalize_confidence_score()` 保留并在失败时给出可诊断信息。

## 测试与验证
- 单元测试：为新客户端、校验器、语言路由、JSON 解析分别添加测试；每个文件函数级注释与示例。
- 集成测试：替换原基于环境的跳过逻辑；在存在最小配置时运行。
- 编译与测试：在 Windows 上执行 `cargo build` 与 `cargo test`；对失败进行修复直至通过。

## 清理与删除
- 删除：`src/locales/ja.rs` 与任何仅用于日文输出的常量；
- 删除：旧的 `genai` 专用封装与适配器代码；
- 保留：tree-sitter 相关文件与测试（不改动）。
- 文档：更新 README/用户指南中的变量说明为配置文件说明；日文示例改为中文与英文。

## 交付物
- 更新后的代码与模块结构；
- 新的 `config/parsentry.toml` 示例模板；
- 双语本地化资源 `zh/en`；
- 通过的构建与测试结果；
- 删除清单与变更记录（不触碰 tree-sitter）。

如您确认以上计划，我将开始实施：依次完成依赖与配置、AI 客户端替换、本地化迁移、测试修复、构建验证与清理删除。