use std::collections::HashMap;

pub struct RequestProfile {
    pub id: &'static str,
    pub user_agent: &'static str,
    pub accept: &'static str,
    pub accept_language: &'static str,
    pub sec_ch_ua: Option<&'static str>,
    pub sec_ch_ua_mobile: Option<&'static str>,
    pub sec_ch_ua_platform: Option<&'static str>,
}

impl RequestProfile {
    pub const PROFILE_STABLE_CHROME: RequestProfile = RequestProfile {
        id: "PROFILE_STABLE_CHROME",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        sec_ch_ua: Some("\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Windows\""),
    };

    pub const PROFILE_STABLE_SAFARI_IOS: RequestProfile = RequestProfile {
        id: "PROFILE_STABLE_SAFARI_IOS",
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        accept_language: "en-US,en;q=0.9",
        sec_ch_ua: None,
        sec_ch_ua_mobile: Some("?1"),
        sec_ch_ua_platform: Some("\"iOS\""),
    };

    pub const PROFILE_STABLE_API: RequestProfile = RequestProfile {
        id: "PROFILE_STABLE_API",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        accept: "application/json, text/plain, */*",
        accept_language: "en-US,en;q=0.9",
        sec_ch_ua: Some("\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""),
        sec_ch_ua_mobile: Some("?0"),
        sec_ch_ua_platform: Some("\"Windows\""),
    };

    pub fn generate_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), self.user_agent.to_string());
        headers.insert("Accept".to_string(), self.accept.to_string());
        headers.insert("Accept-Language".to_string(), self.accept_language.to_string());
        headers.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());
        
        if let Some(ua) = self.sec_ch_ua {
            headers.insert("Sec-Ch-Ua".to_string(), ua.to_string());
        }
        if let Some(mobile) = self.sec_ch_ua_mobile {
            headers.insert("Sec-Ch-Ua-Mobile".to_string(), mobile.to_string());
        }
        if let Some(platform) = self.sec_ch_ua_platform {
            headers.insert("Sec-Ch-Ua-Platform".to_string(), platform.to_string());
        }
        
        headers
    }
}
