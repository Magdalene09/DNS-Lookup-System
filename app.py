from flask import Flask, render_template_string, request
from manual.dns_lookup_manual import dns_lookup

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>DNS Lookup Tool</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; padding-top: 50px; }
        input, button { padding: 10px; font-size: 16px; }
        button { background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        pre { background-color: #eaeaea; padding: 20px; text-align: left; display: inline-block; margin-top: 20px; }
    </style>
</head>
<body>
    <h2>DNS Lookup Tool</h2>
    <form method="POST">
        Domain: <input type="text" name="domain" placeholder="e.g., google.com" required>
        <input type="submit" value="Lookup">
    </form>
    {% if result %}
        <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
'''

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    if request.method == "POST":
        domain = request.form["domain"].strip()
        try:
            result = dns_lookup(domain)
        except Exception as e:
            result = f"Error: {e}"
    return render_template_string(HTML, result=result)

if __name__ == "__main__":
    app.run(debug=True)

