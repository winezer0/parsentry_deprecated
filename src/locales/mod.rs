pub mod en;
pub mod zh;

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Language {
    English,
    Chinese,
}

impl Language {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "en" | "english" => Language::English,
            "zh" | "chinese" => Language::Chinese,
            _ => Language::Chinese,
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            Language::English => "en",
            Language::Chinese => "zh",
        }
    }
}

pub struct LanguageConfig {
    pub language: Language,
}

impl LanguageConfig {
    pub fn new(language: Language) -> Self {
        Self { language }
    }

    pub fn get_message(&self, key: &str) -> &str {
        let messages = get_messages(&self.language);
        messages.get(key).unwrap_or(&"Message not found")
    }

    pub fn get_analysis_prompt(&self) -> &str {
        match self.language {
            Language::English => "Please respond in English",
            Language::Chinese => "请使用中文进行回应",
        }
    }

    pub fn get_response_language_instruction(&self) -> &str {
        get_response_language_instruction(&self.language)
    }
}

pub fn get_messages(lang: &Language) -> HashMap<&'static str, &'static str> {
    match lang {
        Language::English => en::get_messages(),
        Language::Chinese => zh::get_messages(),
    }
}

pub fn get_sys_prompt_template(lang: &Language) -> &'static str {
    match lang {
        Language::English => en::SYS_PROMPT_TEMPLATE,
        Language::Chinese => zh::SYS_PROMPT_TEMPLATE,
    }
}

pub fn get_initial_analysis_prompt_template(lang: &Language) -> &'static str {
    match lang {
        Language::English => en::INITIAL_ANALYSIS_PROMPT_TEMPLATE,
        Language::Chinese => zh::INITIAL_ANALYSIS_PROMPT_TEMPLATE,
    }
}

pub fn get_analysis_approach_template(lang: &Language) -> &'static str {
    match lang {
        Language::English => en::ANALYSIS_APPROACH_TEMPLATE,
        Language::Chinese => zh::ANALYSIS_APPROACH_TEMPLATE,
    }
}

pub fn get_guidelines_template(lang: &Language) -> &'static str {
    match lang {
        Language::English => en::GUIDELINES_TEMPLATE,
        Language::Chinese => zh::GUIDELINES_TEMPLATE,
    }
}

pub fn get_evaluator_prompt_template(lang: &Language) -> &'static str {
    match lang {
        Language::English => en::EVALUATOR_PROMPT_TEMPLATE,
        Language::Chinese => zh::EVALUATOR_PROMPT_TEMPLATE,
    }
}

pub fn get_response_language_instruction(lang: &Language) -> &'static str {
    match lang {
        Language::English => en::RESPONSE_LANGUAGE_INSTRUCTION,
        Language::Chinese => zh::RESPONSE_LANGUAGE_INSTRUCTION,
    }
}
