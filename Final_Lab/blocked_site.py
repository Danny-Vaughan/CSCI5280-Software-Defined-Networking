#!/usr/bin/env python3
"""
Flask app that displays a warning page when a site is blocked.
Run this on your Mac (or in your lab VM) as the web server for 10.0.0.254.
"""

from flask import Flask, render_template_string

app = Flask(__name__)

# ---------------------------------------------------------------------
# HTML template (Bootstrap 5 via CDN)
# ---------------------------------------------------------------------
HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Access Blocked</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body {
        background: linear-gradient(135deg, #f8f9fa, #e9ecef);
        height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .card {
        border: none;
        box-shadow: 0 0 15px rgba(0,0,0,0.1);
        max-width: 500px;
      }
      .icon {
        font-size: 4rem;
        color: #dc3545;
      }
    </style>
  </head>
  <body>
    <div class="container text-center">
      <div class="card p-4">
        <div class="icon mb-3">🚫</div>
        <h2 class="text-danger mb-3">Access Blocked</h2>
        <p class="lead mb-4">
          The website you attempted to visit has been <strong>blocked</strong> by your network administrator.
        </p>
        <p class="text-muted small">
          If you believe this site should be accessible, please contact your IT administrator.
        </p>
        
      </div>
    </div>
  </body>
</html>
"""

# ---------------------------------------------------------------------
@app.route("/", methods=["GET"])
def blocked():
    return render_template_string(HTML)

# ---------------------------------------------------------------------
if __name__ == "__main__":
    # Port 80 requires sudo on macOS/Linux
    app.run(host="0.0.0.0", port=80)
