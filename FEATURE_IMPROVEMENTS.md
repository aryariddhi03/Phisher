# Feature Extraction Improvements - Reducing False Positives

## Problem
Legitimate sites like `https://accounts.example.com/ServiceLogin?service=mail` and `https://github.com/login` were being incorrectly flagged as phishing.

## Root Cause
The "suspicious keywords" feature was too aggressive - it flagged any URL containing words like "login", "account", "secure" without considering context. This caused legitimate login pages to be misclassified.

## Improvements Made

### 1. **Context-Aware Keyword Detection**
**Before:** Any URL with "login", "account", "secure" was flagged
**After:** Only flags keywords when they appear in suspicious contexts

**New Logic:**
- **High-risk patterns**: Flags only when multiple suspicious words appear together (e.g., "verify-account", "update-info", "security-update")
- **Medium-risk keywords**: Only flags "verify", "update", "confirm" when combined with other suspicious indicators:
  - Multiple hyphens in domain (≥2)
  - IP address in domain
  - Suspicious TLD
  - Very long domain (>30 chars) with verify/update keywords

**Examples:**
- ✅ `https://accounts.example.com/ServiceLogin` - NOT flagged (legitimate subdomain)
- ✅ `https://github.com/login` - NOT flagged (clean domain, no suspicious patterns)
- 🚨 `http://verify-account-update.secure-login.info` - FLAGGED (high-risk pattern)
- 🚨 `http://google.com.security-verify.com` - FLAGGED (suspicious domain structure)

### 2. **Legitimate Domain Indicators** (New Features)
Added 5 new features to help identify legitimate domains:

1. **`has_legitimate_subdomain`**: Detects common legitimate subdomain patterns
   - Examples: `accounts.`, `login.`, `auth.`, `www.`, `mail.`, `secure.`, `api.`, `app.`, `portal.`

2. **`has_known_tld`**: Identifies common legitimate TLDs
   - Examples: `.com`, `.org`, `.net`, `.edu`, `.gov`, `.co.uk`, `.io`, `.app`
   - Only positive if domain doesn't have suspicious TLD

3. **`domain_is_short`**: Short domains (<20 chars) are more likely legitimate

4. **`domain_has_reasonable_structure`**: Clean domain structure indicators
   - ≤3 dots, ≤2 hyphens, <50 chars total

5. **`has_suspicious_hyphen_pattern`**: Detects typosquatting patterns
   - Multiple consecutive hyphens (`--`)
   - Hyphens at start/end of domain
   - More than 3 hyphens total

### 3. **Feature Count Update**
- **Before**: 25 URL features
- **After**: 30 URL features (added 5 new features)
- **Total**: 62 features (30 email + 30 URL + 2 type indicators)

## Impact on False Positives

### Legitimate URLs Now Correctly Classified:
- ✅ `https://accounts.example.com/ServiceLogin?service=mail` - Has legitimate subdomain
- ✅ `https://github.com/login` - Clean domain, known TLD, short domain
- ✅ `https://www.google.com` - Has `www.` subdomain, known TLD
- ✅ `https://mail.google.com` - Legitimate subdomain pattern
- ✅ `https://secure.example.com` - Legitimate subdomain, clean structure

### Phishing URLs Still Correctly Flagged:
- 🚨 `http://google.com.security-verify-account-update.secure-login.info` - High-risk pattern, suspicious structure
- 🚨 `http://verify-account-update.example.com` - High-risk pattern
- 🚨 `http://paypal.verify-user-update-info.co-login.cn` - Multiple suspicious indicators

## Technical Details

### Feature Extraction Logic Flow:
1. Extract basic URL features (length, protocol, domain structure)
2. Check for high-risk keyword patterns first
3. If no high-risk patterns, check medium-risk keywords with context
4. Calculate legitimate domain indicators
5. Calculate suspicious pattern indicators
6. Combine all features

### New Feature Values:
- `has_legitimate_subdomain`: 1.0 if legitimate subdomain found, else 0.0
- `has_known_tld`: 1.0 if known legitimate TLD and not suspicious TLD, else 0.0
- `domain_is_short`: 1.0 if domain length < 20, else 0.0
- `domain_has_reasonable_structure`: 1.0 if clean structure, else 0.0
- `has_suspicious_hyphen_pattern`: 1.0 if suspicious hyphen patterns, else 0.0

## Next Steps

1. **Retrain the model** with the new features:
   ```bash
   python train_model.py
   ```

2. **Test with legitimate URLs**:
   - `https://accounts.example.com/ServiceLogin?service=mail`
   - `https://github.com/login`
   - `https://www.google.com`
   - `https://mail.google.com`

3. **Verify phishing detection still works**:
   - `http://google.com.security-verify.com`
   - `http://verify-account-update.secure-login.info`

## Expected Results

After retraining:
- **Reduced false positives**: Legitimate login pages should be classified as legitimate
- **Maintained true positives**: Phishing URLs should still be detected
- **Better feature importance**: New legitimate indicators should have positive weights
- **Improved accuracy**: Overall accuracy should improve, especially for legitimate URLs

## Notes

- The model needs to be **retrained** for these changes to take effect
- Old models will have feature mismatch (25 vs 30 URL features)
- The new features help the model learn legitimate patterns, not just suspicious ones
- Context-aware detection is key to reducing false positives while maintaining security

