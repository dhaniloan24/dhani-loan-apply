# Loan Saathi — Loan Application Portal

यह Flask आधारित शुरुआती वेबसाइट है: customer application form, reference number, status lookup, admin login/dashboard, status update, customer/Aadhaar/PAN file uploads और optional SMTP email notification.

## चलाने का तरीका (local testing)
1. Python 3.10+ install करें.
2. इस folder में virtual environment बनाएं और dependencies install करें:
   - `python -m venv .venv`
   - Windows: `.venv\\Scripts\\activate` | macOS/Linux: `source .venv/bin/activate`
   - `pip install -r requirements.txt`
3. `.env.example` को `.env` नाम से copy करें। अपने hosting/server के environment variables configure करें; app अपने-आप `.env` file load नहीं करता।
4. `FLASK_SECRET_KEY`, `DATA_ENCRYPTION_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` set करें। Encryption key generate करने के लिए:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   Generated key को सुरक्षित रखें; key खोने पर encrypted identity/bank values वापस नहीं पढ़े जा सकेंगे.
5. `python app.py` चलाएं और `http://127.0.0.1:5000` खोलें.
6. Admin: `/admin/login`

## Email setup
SMTP settings environment variables में भरें। `SMTP_HOST` unset हो तो email बंद रहेगा। Admin notification `ADMIN_NOTIFY_EMAIL` पर जाती है। इस starter में applicant का email field नहीं है, इसलिए applicant को email update नहीं भेजा जाता।

## महत्वपूर्ण सुरक्षा / production checklist
- यह starter है, audited production lending platform नहीं। असली Aadhaar/PAN/bank data के लिए deploy करने से पहले भारत में लागू कानूनों, Aadhaar-related rules, DPDP/privacy requirements, consent, purpose limitation, retention/deletion, grievance contact और organisation की authorisation की कानूनी समीक्षा कराएं.
- Aadhaar authentication या UIDAI verification इस वेबसाइट में शामिल नहीं है। बिना वैध अधिकार के Aadhaar data collect/store न करें; जहाँ संभव हो masked Aadhaar/वैकल्पिक KYC अपनाएं.
- HTTPS/TLS, secure hosting, firewall, encrypted backups, monitoring, regular updates, rate limiting, CSRF protection, admin MFA, audit log, antivirus/file scanning, backup key management और retention policy production में जोड़ना आवश्यक है.
- Uploaded documents `private_uploads/` में रखे जाते हैं और केवल logged-in admin route से डाउनलोड हो सकते हैं। इस folder को web server पर static/public directory न बनाएं.
- Admin password और encryption key को code में न डालें। `.env`/secrets को public repository या ZIP में वास्तविक credentials के साथ कभी न रखें.
- पहली बार admin account तभी बनता है जब खाली database के साथ `ADMIN_PASSWORD` set हो। Password बदलने के लिए database admin management procedure की आवश्यकता होगी; production में dedicated password reset/management flow जोड़ें.
- Public deployment से पहले security audit और legal/privacy review कराएं. Demo के लिए synthetic data ही उपयोग करें.
