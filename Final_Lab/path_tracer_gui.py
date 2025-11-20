from flask import Flask, render_template_string, request
from tracer import SimpleTracer

app = Flask(__name__)
t = SimpleTracer(controller="127.0.0.1", port=8080)

HTML = """
<h1>SDN Flow Tracer</h1>
<form method="post">
  Switch DPID: <input name="dpid" required><br><br>
  Ingress Port: <input name="port" required><br><br>
  Destination IP: <input name="dst" required><br><br>
  <input type="submit" value="Trace">
</form>

{% if result %}
<h2>Trace Results</h2>
<table border="1" cellpadding="6">
<tr><th>DPID</th><th>In</th><th>Out</th><th>Note</th></tr>
{% for hop in result %}
<tr>
  <td>{{ hop.dpid }}</td>
  <td>{{ hop.in_port }}</td>
  <td>{{ hop.out_port }}</td>
  <td>{{ hop.note if hop.note else "" }}</td>
</tr>
{% endfor %}
</table>
{% endif %}
"""

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        dpid = request.form["dpid"]
        port = request.form["port"]
        dst  = request.form["dst"]
        result = t.trace(dpid, port, dst)
        return render_template_string(HTML, result=result)

    return render_template_string(HTML)

app.run(host="0.0.0.0", port=5005, debug=True)
