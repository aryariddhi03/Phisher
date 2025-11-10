import os
import joblib
import pandas as pd
import streamlit as st
import urllib.parse
import re
import numpy as np

# Import unified feature extraction from train_model
try:
    from train_model import (
        extract_unified_features,
        extract_comprehensive_url_features,
        extract_email_features,
        detect_input_type
    )
except ImportError:
    # Fallback if import fails
    def extract_unified_features(content: str):
        return [0.0] * 57
    def detect_input_type(content: str):
        return 'url' if content.startswith(('http://', 'https://')) else 'email'


def extract_comprehensive_url_features_legacy(url: str):
    """
    Extract comprehensive features from a URL string for phishing detection.
    Returns a list of 25 features matching the training data.
    """
    if not isinstance(url, str):
        url = str(url)
    
    url = url.strip()
    if not url:
        return [0.0] * 25
    
    try:
        parsed = urllib.parse.urlparse(url)
    except:
        return [0.0] * 25
    
    url_lower = url.lower()
    
    # Basic URL features
    url_length = len(url)
    protocol = parsed.scheme
    has_https = 1.0 if protocol == 'https' else 0.0
    has_http = 1.0 if protocol == 'http' else 0.0
    has_ftp = 1.0 if protocol == 'ftp' else 0.0
    
    # Domain features
    domain = parsed.netloc
    domain_length = len(domain) if domain else 0
    num_dots = domain.count('.') if domain else 0
    num_hyphens = domain.count('-') if domain else 0
    num_underscores = domain.count('_') if domain else 0
    num_slashes = domain.count('/') if domain else 0
    num_question_marks = domain.count('?') if domain else 0
    num_equal_signs = domain.count('=') if domain else 0
    num_at_symbols = domain.count('@') if domain else 0
    num_tildes = domain.count('~') if domain else 0
    num_percentages = domain.count('%') if domain else 0
    
    # Path features
    path = parsed.path
    path_length = len(path)
    num_digits = sum(c.isdigit() for c in url)
    num_letters = sum(c.isalpha() for c in url)
    
    # Security and suspicious features
    has_port = 1.0 if ':' in domain and domain.split(':')[1].isdigit() else 0.0
    has_ip = 1.0 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain) else 0.0
    has_suspicious_tld = 1.0 if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0.0
    
    # Suspicious keywords
    suspicious_keywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'bank', 'paypal']
    has_suspicious_keywords = 1.0 if any(keyword in url_lower for keyword in suspicious_keywords) else 0.0
    
    # Entropy (randomness measure)
    if len(url) > 1:
        char_freq = {}
        for char in url:
            char_freq[char] = char_freq.get(char, 0) + 1
        entropy = -sum((freq/len(url)) * np.log2(freq/len(url)) for freq in char_freq.values())
    else:
        entropy = 0.0
    
    # URL depth (number of slashes in path)
    url_depth = path.count('/') if path else 0
    
    return [
        url_length, domain_length, path_length, num_dots, num_hyphens, num_underscores,
        num_slashes, num_question_marks, num_equal_signs, num_at_symbols, num_tildes,
        num_percentages, num_digits, num_letters, has_https, has_http, has_ftp,
        has_port, has_ip, has_suspicious_tld, has_suspicious_keywords, entropy,
        url_depth, protocol == '', len(domain) if domain else 0
    ]


@st.cache_resource
def load_model():
    """Load the trained phishing detection model."""
    # Try to load the comprehensive model bundle first
    model_path = os.path.join(os.path.dirname(__file__), 'phishing_models.pkl')
    if os.path.exists(model_path):
        bundle = joblib.load(model_path)
        # Check if it's the new unified model
        if 'feature_extractor' in bundle and 'extract_unified_features' in str(bundle.get('feature_extractor', '')):
            return bundle['random_forest'], bundle['feature_names'], bundle['scaler'], bundle.get('feature_extractor', None)
        return bundle['random_forest'], bundle['feature_names'], bundle['scaler'], None
    
    # Fallback to the individual model
    model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
    if os.path.exists(model_path):
        bundle = joblib.load(model_path)
        return bundle['model'], bundle['feature_names'], bundle.get('scaler', None), None
    
    raise FileNotFoundError("No trained model found. Please run train_model.py first.")


def analyze_url(url: str):
    """
    Provide human-readable risk signals and suggestions based on the raw URL string.
    """
    url_str = (url or "").strip()
    url_lc = url_str.lower()
    
    signals = []
    risk_score = 0
    
    # Protocol analysis
    if url_lc.startswith("http://"):
        signals.append("🚨 Uses HTTP instead of HTTPS (insecure)")
        risk_score += 2
    elif url_lc.startswith("https://"):
        signals.append("✅ Uses HTTPS (secure)")
        risk_score -= 1
    
    # Domain analysis
    if url_lc.count("@") > 0:
        signals.append("🚨 Contains '@' which can hide real destination")
        risk_score += 3
    
    if url_lc.count("-") >= 3:
        signals.append("⚠️ Many hyphens in domain/path (suspicious)")
        risk_score += 1
    
    if url_lc.count(".") >= 4:
        signals.append("⚠️ Unusually many dots (subdomains)")
        risk_score += 1
    
    if len(url_lc) > 80:
        signals.append("⚠️ Very long URL")
        risk_score += 1
    
    # IP address detection
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url_lc):
        signals.append("🚨 Contains IP address instead of domain")
        risk_score += 3
    
    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    if any(tld in url_lc for tld in suspicious_tlds):
        signals.append("🚨 Uses suspicious top-level domain")
        risk_score += 2
    
    # Suspicious keywords
    suspicious_keywords = [
        "verify", "update", "secure", "confirm", "login", "password", 
        "account", "bank", "paypal", "billing", "security"
    ]
    if any(k in url_lc for k in suspicious_keywords):
        signals.append("⚠️ Contains urgency/authentication keywords")
        risk_score += 1
    
    # Port analysis
    if ':' in url_lc and any(port in url_lc for port in [':80', ':8080', ':3000']):
        signals.append("⚠️ Uses non-standard port")
        risk_score += 1
    
    # Actionable suggestions
    suggestions = [
        "🔒 Do not enter passwords or OTPs on this page",
        "🔍 Open a new tab and type the known official domain manually",
        "📝 Check the domain spelling (look for letter swaps or extra words)",
        "🔐 Look for HTTPS and a valid certificate (lock icon)",
        "📧 If received via email/SMS, verify sender and avoid clicking links",
        "🌐 Check if the domain is registered recently",
        "📱 Use official apps instead of clicking links when possible"
    ]
    
    # Risk level determination
    if risk_score >= 5:
        risk_level = "🚨 HIGH RISK"
    elif risk_score >= 3:
        risk_level = "⚠️ MEDIUM RISK"
    elif risk_score >= 1:
        risk_level = "🔶 LOW RISK"
    else:
        risk_level = "✅ LOW RISK"
    
    return signals, suggestions, risk_level, risk_score


def analyze_email(email_content: str):
    """
    Provide human-readable risk signals for emails.
    """
    email_lower = (email_content or "").lower()
    signals = []
    risk_score = 0
    
    # Sender analysis
    if 'from:' in email_lower:
        sender_match = re.search(r'from:\s*([^\n]+)', email_lower)
        if sender_match:
            sender = sender_match.group(1).strip()
            if any(susp in sender for susp in ['verify', 'security', 'update', 'billing']):
                signals.append("🚨 Suspicious sender domain")
                risk_score += 2
    
    # Subject analysis
    if 'subject:' in email_lower:
        subject_match = re.search(r'subject:\s*([^\n]+)', email_lower)
        if subject_match:
            subject = subject_match.group(1).strip()
            if 'urgent' in subject.lower() or '!' in subject:
                signals.append("⚠️ Urgent/emotional language in subject")
                risk_score += 1
            if subject.isupper() and len(subject) > 5:
                signals.append("⚠️ Subject in all caps")
                risk_score += 1
    
    # URL analysis within email
    url_pattern = r'http[s]?://[^\s]+'
    urls = re.findall(url_pattern, email_content)
    if urls:
        for url in urls:
            if 'http://' in url.lower():
                signals.append("🚨 Email contains insecure HTTP link")
                risk_score += 2
            if any(susp in url.lower() for susp in ['verify', 'update', 'login', 'secure']):
                signals.append("⚠️ Suspicious link in email")
                risk_score += 1
    
    # Keyword analysis
    urgency_words = ['urgent', 'immediately', 'asap', 'act now']
    financial_words = ['payment', 'billing', 'invoice', 'refund']
    if any(word in email_lower for word in urgency_words):
        signals.append("⚠️ Urgency keywords detected")
        risk_score += 1
    if any(word in email_lower for word in financial_words):
        signals.append("⚠️ Financial keywords detected")
        risk_score += 1
    
    return signals, risk_score


def main():
    st.set_page_config(
        page_title="Phishing Detection (URLs & Emails)", 
        page_icon="🔒", 
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🔒 Advanced Phishing Detection")
    st.markdown("Analyze URLs or emails to detect potential phishing attempts using our comprehensive ML model.")
    
    # Sidebar
    st.sidebar.header("📊 Model Information")
    st.sidebar.markdown("""
    **Features Used:**
    - URL structure analysis
    - Email content analysis
    - Domain characteristics
    - Security indicators
    - Suspicious patterns
    - Entropy analysis
    
    **Model:** Random Forest Classifier
    **Supports:** URLs and Emails
    """)
    
    try:
        model_result = load_model()
        if len(model_result) == 4:
            model, feature_names, scaler, feature_extractor = model_result
        else:
            model, feature_names, scaler = model_result
            feature_extractor = None
        
        # Try to load optimal threshold from model bundle
        try:
            bundle = joblib.load(os.path.join(os.path.dirname(__file__), 'phishing_models.pkl'))
            optimal_threshold_model = bundle.get('optimal_threshold', 0.5)
        except:
            optimal_threshold_model = 0.5
        
        st.sidebar.success("✅ Model loaded successfully")
        if optimal_threshold_model != 0.5:
            st.sidebar.info(f"💡 Model optimal threshold: {optimal_threshold_model:.3f}")
    except Exception as e:
        st.error("❌ Model not found. Please run the training script first: `python train_model.py`")
        st.exception(e)
        return
    
    # Detection sensitivity
    sensitivity_choice = st.sidebar.selectbox(
        "🎚️ Detection sensitivity",
        ["Aggressive (more alerts)", "Balanced (optimal)", "Conservative (fewer alerts)"],
        index=1,  # Default to balanced/optimal
        help="Aggressive lowers the threshold to flag phishing, Conservative raises it. Balanced uses the model's optimal threshold."
    )
    if sensitivity_choice == "Aggressive (more alerts)":
        phishing_threshold = 0.35
    elif sensitivity_choice == "Balanced (optimal)":
        phishing_threshold = optimal_threshold_model if 'optimal_threshold_model' in locals() else 0.50
    else:
        phishing_threshold = 0.65
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Input type selection
        input_type = st.radio(
            "📝 Select input type:",
            ["URL", "Email"],
            horizontal=True,
            help="Choose whether you want to analyze a URL or an email"
        )
        
        if input_type == "URL":
            content_input = st.text_input(
                "🔗 Enter URL to analyze:", 
                placeholder="e.g., https://example.com/login",
                help="Enter the complete URL including protocol (http:// or https://)"
            )
            analyze_button_text = "🔍 Analyze URL"
        else:
            content_input = st.text_area(
                "📧 Enter email to analyze:",
                placeholder="From: sender@domain.com\nSubject: Subject line\nBody: Email body content...",
                height=200,
                help="Enter email content with From, Subject, and Body fields (or raw email text)"
            )
            analyze_button_text = "🔍 Analyze Email"
        
        if st.button(analyze_button_text, type="primary", use_container_width=True):
            if not content_input:
                st.warning(f"⚠️ Please enter a {input_type.lower()}.")
                return
            
            # Detect actual type (may differ from user selection)
            detected_type = detect_input_type(content_input)
            
            with st.spinner(f"🔍 Analyzing {detected_type.upper()}..."):
                # Extract features using unified extractor
                if feature_extractor is not None:
                    # Use the unified feature extractor from model
                    features = feature_extractor(content_input)
                else:
                    # Fallback to unified extraction
                    try:
                        features = extract_unified_features(content_input)
                    except:
                        # Legacy fallback for old models
                        if detected_type == 'url':
                            features = extract_comprehensive_url_features_legacy(content_input)
                            # Pad with zeros for email features if needed
                            if len(feature_names) > 25:
                                features = [0.0] * (len(feature_names) - 25) + features
                        else:
                            features = [0.0] * len(feature_names)
                
                # Ensure feature count matches
                if len(features) != len(feature_names):
                    st.warning(f"⚠️ Feature mismatch: expected {len(feature_names)}, got {len(features)}. Using available features.")
                    # Pad or truncate as needed
                    if len(features) < len(feature_names):
                        features = features + [0.0] * (len(feature_names) - len(features))
                    else:
                        features = features[:len(feature_names)]
                
                X = pd.DataFrame([features], columns=feature_names)
                
                # Scale features if scaler exists
                if scaler is not None:
                    X_scaled = scaler.transform(X)
                else:
                    X_scaled = X
                
                # Make prediction
                pred = int(model.predict(X_scaled)[0])
                pred_proba = None
                if hasattr(model, 'predict_proba'):
                    try:
                        pred_proba = model.predict_proba(X_scaled)[0]
                    except:
                        pred_proba = None
                
                # Use probability threshold to determine final decision
                final_pred = pred
                phishing_prob = None
                heuristic_override_note = None
                if pred_proba is not None:
                    if len(pred_proba) > 1:
                        phishing_prob = float(pred_proba[1])
                    else:
                        phishing_prob = 1.0 - float(pred_proba[0])
                    
                    # Adjust threshold for clean domains (be more conservative)
                    adjusted_threshold = phishing_threshold
                    if detected_type == 'url':
                        try:
                            parsed = urllib.parse.urlparse(content_input)
                            domain = parsed.netloc.lower() if parsed.netloc else ""
                            if ':' in domain:
                                domain = domain.split(':')[0]
                            
                            # If it's a clean domain with HTTPS, be more conservative (raise threshold)
                            if content_lc.startswith('https://'):
                                domain_parts = domain.split('.')
                                if len(domain_parts) <= 3:
                                    main_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
                                    if len(main_domain) < 25 and '-' not in main_domain.split('.')[0] if '.' in main_domain else True:
                                        # Clean domain with HTTPS - require higher confidence for phishing
                                        adjusted_threshold = min(0.7, phishing_threshold + 0.15)
                        except:
                            pass
                    
                    final_pred = 1 if phishing_prob >= adjusted_threshold else 0

                # Heuristic overrides based on content type
                heuristic_override_note = None
                try:
                    content_lc = (content_input or "").lower().strip()
                    
                    if detected_type == 'url':
                        # Extract domain from URL
                        try:
                            parsed = urllib.parse.urlparse(content_input)
                            domain = parsed.netloc.lower() if parsed.netloc else ""
                            # Remove port if present
                            if ':' in domain:
                                domain = domain.split(':')[0]
                        except:
                            domain = ""
                        
                        # Pattern-based legitimate domain detection (works for ALL domains)
                        is_legitimate = False
                        legitimate_reasons = []
                        
                        # Check for clean domain structure with known TLDs
                        clean_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co.uk', '.dev', '.tech',
                                     '.info', '.biz', '.us', '.uk', '.ca', '.au', '.de', '.fr', '.jp', '.cn']
                        
                        if domain:
                            domain_parts = domain.split('.')
                            main_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
                            main_domain_name = main_domain.split('.')[0] if '.' in main_domain else main_domain
                            
                            # Legitimate indicators (all must be checked)
                            has_clean_tld = any(domain.endswith(tld) for tld in clean_tlds)
                            has_https = content_lc.startswith('https://')
                            is_short_domain = len(main_domain) < 25
                            has_clean_name = '-' not in main_domain_name and len(main_domain_name) < 20
                            has_reasonable_structure = len(domain_parts) <= 3
                            has_few_hyphens = domain.count('-') <= 1
                            no_suspicious_tld = not any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq'])
                            no_ip_address = not re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain)
                            no_at_symbol = '@' not in domain
                            
                            # Legitimate subdomain patterns
                            legitimate_subdomains = ['www.', 'accounts.', 'login.', 'auth.', 'mail.', 'secure.', 
                                                   'api.', 'app.', 'portal.', 'signin.', 'my.', 'admin.', 
                                                   'dashboard.', 'service.', 'web.', 'shop.', 'store.', 
                                                   'blog.', 'news.', 'help.', 'support.', 'docs.']
                            has_legitimate_subdomain = any(sub in domain.lower() for sub in legitimate_subdomains)
                            
                            # Score-based legitimacy check
                            legitimacy_score = 0
                            if has_https:
                                legitimacy_score += 3
                                legitimate_reasons.append("HTTPS")
                            if has_clean_tld and no_suspicious_tld:
                                legitimacy_score += 2
                                legitimate_reasons.append("Known TLD")
                            if is_short_domain:
                                legitimacy_score += 1
                                legitimate_reasons.append("Short domain")
                            if has_clean_name:
                                legitimacy_score += 2
                                legitimate_reasons.append("Clean domain name")
                            if has_reasonable_structure:
                                legitimacy_score += 1
                                legitimate_reasons.append("Reasonable structure")
                            if has_few_hyphens:
                                legitimacy_score += 1
                                legitimate_reasons.append("Few hyphens")
                            if has_legitimate_subdomain:
                                legitimacy_score += 2
                                legitimate_reasons.append("Legitimate subdomain")
                            if no_ip_address:
                                legitimacy_score += 1
                            if no_at_symbol:
                                legitimacy_score += 1
                            
                            # Suspicious indicators (reduce score)
                            domain_hyphen_count = domain.count('-')
                            if domain_hyphen_count >= 3:
                                legitimacy_score -= 2
                            if len(domain) > 50:
                                legitimacy_score -= 1
                            if '--' in domain or domain.startswith('-') or domain.endswith('-'):
                                legitimacy_score -= 2
                            
                            # If legitimacy score is high enough, treat as legitimate
                            # Threshold: 7+ points = likely legitimate
                            if legitimacy_score >= 7 and has_https and has_clean_tld:
                                is_legitimate = True
                        
                        if is_legitimate:
                            # Override to legitimate based on pattern analysis
                            final_pred = 0
                            # Reduce phishing probability significantly
                            if phishing_prob is not None:
                                phishing_prob = max(0.05, phishing_prob * 0.2)
                            else:
                                phishing_prob = 0.1
                            heuristic_override_note = f"✅ Legitimate domain pattern detected ({', '.join(legitimate_reasons[:3])})"
                        
                        # URL-specific heuristics for phishing
                        ip_present = re.search(r'\b\d{1,3}\.(?:\d{1,3}\.){2}\d{1,3}\b', content_lc) is not None
                        at_present = "@" in content_lc
                        if (ip_present or at_present) and not is_legitimate:
                            final_pred = 1
                            heuristic_override_note = "Heuristic override: " + ("IP address detected" if ip_present else "'@' detected")
                    else:
                        # Email-specific heuristics
                        url_pattern = r'http[s]?://[^\s]+'
                        urls_in_email = re.findall(url_pattern, content_input)
                        suspicious_url_found = False
                        for url in urls_in_email:
                            if 'http://' in url.lower() or any(susp in url.lower() for susp in ['verify', 'update', 'login', 'secure']):
                                suspicious_url_found = True
                                break
                        if suspicious_url_found:
                            risk_score += 2
                except Exception:
                    pass
                
                # Display results
                st.markdown("---")
                
                # Result banner based on final decision
                if final_pred == 1:
                    if detected_type == 'email':
                        st.error("🚨 **PHISHING EMAIL DETECTED**")
                    else:
                        st.error("🚨 **PHISHING URL DETECTED**")
                    if phishing_prob is not None:
                        st.markdown(f"**Phishing probability:** {phishing_prob:.1%} (threshold {phishing_threshold:.2f})")
                else:
                    if detected_type == 'email':
                        st.success("✅ **LEGITIMATE EMAIL**")
                    else:
                        st.success("✅ **LEGITIMATE URL**")
                    if phishing_prob is not None:
                        st.markdown(f"**Phishing probability:** {phishing_prob:.1%} (threshold {phishing_threshold:.2f})")
                
                if heuristic_override_note:
                    st.info(f"ℹ️ {heuristic_override_note}")
                
                # Risk analysis based on content type
                if detected_type == 'email':
                    email_signals, email_risk_score = analyze_email(content_input)
                    # Merge with URL analysis if URLs are found in email
                    url_signals = []
                    if any(url in content_input.lower() for url in ['http://', 'https://']):
                        url_pattern = r'http[s]?://[^\s]+'
                        urls = re.findall(url_pattern, content_input)
                        for url in urls:
                            url_sig, _, _, _ = analyze_url(url)
                            url_signals.extend(url_sig)
                    signals = email_signals + url_signals
                    risk_score = email_risk_score
                    suggestions = [
                        "🔒 Never click links in suspicious emails",
                        "🔍 Verify sender email address carefully",
                        "📧 Check if the sender domain matches the company",
                        "🚫 Do not download attachments from unknown senders",
                        "🔐 Use official websites/apps instead of clicking email links",
                        "📞 Contact the company directly if you're unsure",
                        "⚠️ Look for spelling and grammar errors"
                    ]
                else:
                    signals, suggestions, risk_level, risk_score = analyze_url(content_input)

                # Override/align risk using model output so phishing is never labeled low risk
                # Normalize heuristic score and combine with model confidence
                try:
                    heuristic_score = int(risk_score)
                except Exception:
                    heuristic_score = 0

                # Cap within [0,10]
                heuristic_score = max(0, min(10, heuristic_score))

                # If final decision is phishing, ensure score reflects high risk
                if final_pred == 1:
                    if phishing_prob is not None:
                        model_score = int(round(phishing_prob * 10))
                    else:
                        model_score = 8  # sensible default high risk
                    risk_score = max(heuristic_score, max(7, model_score))
                else:
                    risk_score = heuristic_score

                # Final bounds
                risk_score = max(0, min(10, int(risk_score)))

                # Derive final risk level from the adjusted score
                if risk_score >= 7:
                    risk_level = "🚨 HIGH RISK"
                elif risk_score >= 3:
                    risk_level = "⚠️ MEDIUM RISK"
                elif risk_score >= 1:
                    risk_level = "🔶 LOW RISK"
                else:
                    risk_level = "✅ LOW RISK"
                
                st.subheader("🔍 Risk Analysis")
                st.markdown(f"**Risk Level:** {risk_level}")
                st.markdown(f"**Risk Score:** {risk_score}/10")
                
                if signals:
                    st.markdown("**Detected Signals:**")
                    for signal in signals:
                        st.markdown(f"- {signal}")
                else:
                    st.markdown("✅ No obvious heuristic red flags detected")
                
                # Feature breakdown
                with st.expander("🔬 Feature Analysis"):
                    feature_df = pd.DataFrame({
                        'Feature': feature_names,
                        'Value': features
                    })
                    st.dataframe(feature_df, use_container_width=True)
    
    with col2:
        st.subheader("📋 Quick Tips")
        st.markdown("""
        **Always verify:**
        - ✅ HTTPS protocol
        - ✅ Official domain spelling
        - ✅ Valid SSL certificate
        - ✅ No suspicious redirects
        
        **Be cautious of:**
        - 🚨 HTTP instead of HTTPS
        - 🚨 IP addresses in URLs
        - 🚨 Many hyphens or dots
        - 🚨 Suspicious TLDs (.tk, .ml)
        """)
        
        st.subheader("📱 Test Examples")
        st.markdown("""
        **Legitimate URLs:**
        - https://www.google.com
        - https://github.com
        
        **Suspicious URLs:**
        - http://google.com.security-verify.com
        - http://paypal.verify-account.net
        
        **Email Format:**
        ```
        From: sender@domain.com
        Subject: Subject line
        Body: Email body content...
        ```
        """)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "🔒 **Disclaimer:** This tool is for educational purposes. Always use your judgment and verify URLs independently."
    )


if __name__ == "__main__":
    main()


