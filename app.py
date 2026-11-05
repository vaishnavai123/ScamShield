from flask import Flask, render_template, request
import re

app = Flask(__name__)

# Suspicious message patterns and their risk scores
SCAM_PATTERNS = {
    "Urgent or threatening language": {
        "patterns": [
            r"\bimmediately\b",
            r"\burgent\b",
            r"\bact now\b",
            r"\baccount.{0,30}\bblocked\b",
            r"\baccount.{0,30}\bsuspended\b",
            r"\bwithin 24 hours\b"
        ],
        "score": 20
    },

    "OTP or credential request": {
        "patterns": [
            r"\botp\b",
            r"\bshare.{0,20}\bpassword\b",
            r"\bpassword.{0,20}\bshare\b",
            r"\bpin number\b",
            r"\bverification code\b",
            r"\bcvv\b"
        ],
        "score": 30
    },

    "Money or payment request": {
        "patterns": [
            r"\bsend money\b",
            r"\bpay now\b",
            r"\bclaim.{0,20}\bprize\b",
            r"\bprocessing fee\b",
            r"\btransfer money\b",
            r"\bpayment required\b"
        ],
        "score": 25
    },

    "Suspicious link indicators": {
        "patterns": [
            r"http://",
            r"\bbit\.ly\b",
            r"\btinyurl\.com\b",
            r"\bclick here\b",
            r"\bverify.{0,20}\baccount\b"
        ],
        "score": 20
    },

    "Unexpected prize or reward": {
        "patterns": [
            r"\byou have won\b",
            r"\bcongratulations.{0,40}\bprize\b",
            r"\blottery winner\b",
            r"\bfree gift\b",
            r"\bclaim your reward\b"
        ],
        "score": 20
    }
}


def analyse_message(message):
    findings = []
    matched_patterns = set()
    risk_score = 0

    text = message.lower()

    for category, details in SCAM_PATTERNS.items():
        category_matched = False

        for pattern in details["patterns"]:
            if re.search(pattern, text):
                category_matched = True
                matched_patterns.add(pattern)

        if category_matched:
            findings.append(category)
            risk_score += details["score"]

    # Limit the score to 100
    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        risk_level = "HIGH"
        recommendation = (
            "Do not click suspicious links or share sensitive information. "
            "Verify the message through the organisation's official channel."
        )

    elif risk_score >= 30:
        risk_level = "MEDIUM"
        recommendation = (
            "Be cautious. Verify the sender and avoid sharing passwords, "
            "OTPs or financial information."
        )

    else:
        risk_level = "LOW"
        recommendation = (
            "Few known warning signs were detected. This does not guarantee "
            "that the message is genuine. Verify unexpected requests."
        )

    if not findings:
        findings.append("No known scam patterns detected")

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendation": recommendation
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message:
            result = analyse_message(message)

    return render_template(
        "index.html",
        result=result,
        message=message
    )


if __name__ == "__main__":
    app.run(debug=True)