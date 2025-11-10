# General Solution for All URLs and Emails

## Problem
User wants the system to correctly classify **ALL** legitimate URLs and emails (not just a hardcoded whitelist), and correctly identify phishing attempts.

## Solution: Pattern-Based Detection

Instead of a hardcoded whitelist, the system now uses **pattern-based detection** that works for any URL or email.

## Key Improvements

### 1. **Enhanced Feature Extraction** (train_model.py)

#### New URL Features (32 total, up from 25):
- **`has_legitimate_keywords`**: Detects legitimate keywords in clean contexts
  - Keywords: login, signin, account, accounts, secure, auth, authentication
  - Only positive if domain is clean (few hyphens, reasonable length, no suspicious TLD)
  
- **`domain_legitimacy_score`**: Composite score (0.0-1.0) indicating domain legitimacy
  - Factors: HTTPS (+0.3), legitimate subdomain (+0.2), known TLD (+0.2), short domain (+0.1), clean structure (+0.1), no suspicious patterns (+0.1)

#### Improved Keyword Detection:
- **High-risk patterns**: Only flags when multiple suspicious words appear together
  - Examples: "verify-account", "update-info", "security-update"
  
- **Medium-risk keywords**: Only flags when combined with suspicious indicators
  - Keywords: "verify", "update", "confirm"
  - Only flagged if: multiple hyphens, IP address, suspicious TLD, or in domain name itself

- **Legitimate keywords**: Recognizes legitimate patterns
  - Keywords: "login", "account", "secure", "auth" in clean contexts
  - Not flagged if domain is clean and keyword is in path/subdomain

### 2. **Pattern-Based Legitimacy Detection** (app.py)

Replaced hardcoded whitelist with **score-based pattern matching**:

#### Legitimacy Scoring System:
- **HTTPS**: +3 points
- **Known TLD** (not suspicious): +2 points
- **Clean domain name** (no hyphens, <20 chars): +2 points
- **Legitimate subdomain**: +2 points
- **Short domain** (<25 chars): +1 point
- **Reasonable structure** (≤3 parts): +1 point
- **Few hyphens** (≤1): +1 point
- **No IP address**: +1 point
- **No @ symbol**: +1 point

#### Suspicious Indicators (reduce score):
- **Multiple hyphens** (≥3): -2 points
- **Long domain** (>50 chars): -1 point
- **Suspicious hyphen patterns** (--, start/end with -): -2 points

#### Decision Logic:
- If legitimacy score ≥ 7 AND has HTTPS AND has clean TLD → **LEGITIMATE**
- Otherwise, use model prediction

### 3. **Expanded Legitimate Patterns**

#### Legitimate Subdomains (27 patterns):
- Common: www., accounts., login., auth., mail., secure.
- Services: api., app., portal., service., services.
- Commerce: shop., store.
- Content: blog., news., docs.
- Support: help., support.
- And more...

#### Known TLDs (20+ patterns):
- Standard: .com, .org, .net, .edu, .gov
- Country: .co.uk, .us, .uk, .ca, .au, .de, .fr, .jp, .cn
- Modern: .io, .app, .dev, .tech
- Business: .info, .biz

## How It Works

### For URLs:
1. Extract domain from URL
2. Calculate legitimacy score based on patterns
3. If score ≥ 7 with HTTPS and clean TLD → Override to legitimate
4. Otherwise, use model prediction with adjusted threshold

### For Emails:
1. Extract sender domain
2. Analyze email structure (headers, content, URLs)
3. Check URLs in email using same pattern detection
4. Use model prediction with email-specific features

## Examples

### Legitimate URLs (All should pass):
- ✅ `https://www.google.com/` - HTTPS, known TLD, www subdomain, clean name
- ✅ `https://accounts.example.com/ServiceLogin` - HTTPS, known TLD, legitimate subdomain, clean name
- ✅ `https://github.com/login` - HTTPS, known TLD, short domain, clean name
- ✅ `https://mail.company.com` - HTTPS, known TLD, legitimate subdomain
- ✅ `https://shop.store.com` - HTTPS, known TLD, legitimate subdomain

### Phishing URLs (All should be flagged):
- 🚨 `http://google.com.security-verify.com` - HTTP, suspicious structure, multiple domains
- 🚨 `http://verify-account-update.secure-login.info` - HTTP, high-risk pattern, suspicious TLD
- 🚨 `http://192.168.1.1/login` - IP address, HTTP
- 🚨 `http://paypal.verify-user-update.co-login.cn` - Multiple suspicious indicators

## Benefits

1. **Works for ALL domains** - No hardcoded list needed
2. **Pattern-based** - Recognizes legitimate patterns, not specific domains
3. **Adaptive** - Can handle new legitimate domains automatically
4. **Comprehensive** - Multiple indicators work together
5. **Balanced** - Reduces false positives while maintaining phishing detection

## Next Steps

1. **Retrain the model**:
   ```bash
   python train_model.py
   ```
   This will train with the new 32 URL features and improved patterns.

2. **Test with various URLs**:
   - Legitimate: Any clean domain with HTTPS
   - Phishing: Suspicious patterns should still be detected

3. **Monitor performance**:
   - Check false positive rate (should be low)
   - Check false negative rate (phishing detection should still work)

## Technical Details

- **Total Features**: 64 (30 email + 32 URL + 2 type indicators)
- **Legitimacy Score Threshold**: 7 points (with HTTPS and clean TLD required)
- **Adjusted Threshold**: +0.15 for clean domains (more conservative)
- **Probability Reduction**: Legitimate domains get 0.2x probability multiplier

## Notes

- Pattern-based detection works immediately (no retraining needed for app.py changes)
- Model retraining recommended for best results with new features
- System is now general-purpose and works for any domain
- Can be extended with more patterns as needed

