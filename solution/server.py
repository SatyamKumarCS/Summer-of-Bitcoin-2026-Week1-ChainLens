# Flask server for the web visualizer

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template
from src.main import analyze_transaction, error_response
from src.block import parse_block_file

app = Flask(__name__, template_folder="templates")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"ok": True})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify(error_response("INVALID_INPUT", "Could not parse JSON body")), 400

    raw_tx = data.get("raw_tx", "")
    prevouts = data.get("prevouts", [])
    network = data.get("network", "mainnet")

    if not raw_tx:
        return jsonify(error_response("INVALID_INPUT", "Missing raw_tx")), 400

    try:
        result = analyze_transaction(raw_tx, prevouts, network)
        return jsonify(result)
    except Exception as e:
        return jsonify(error_response("INVALID_TX", str(e))), 400


@app.route("/api/analyze-block", methods=["POST"])
def analyze_block():
    blk_file = request.files.get("blk")
    rev_file = request.files.get("rev")
    xor_file = request.files.get("xor")

    if not blk_file or not rev_file or not xor_file:
        return jsonify(error_response("INVALID_INPUT", "Must upload blk, rev, and xor files")), 400

    tmpdir = tempfile.mkdtemp()
    try:
        blk_path = os.path.join(tmpdir, "blk.dat")
        rev_path = os.path.join(tmpdir, "rev.dat")
        xor_path = os.path.join(tmpdir, "xor.dat")

        blk_file.save(blk_path)
        rev_file.save(rev_path)
        xor_file.save(xor_path)

        results = parse_block_file(blk_path, rev_path, xor_path)

        # read results back from out/ and return them
        out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
        block_results = []
        if results and isinstance(results, list):
            for r in results:
                block_results.append(r)
        else:
            # fallback: read JSON files from out/
            if os.path.isdir(out_dir):
                for fname in sorted(os.listdir(out_dir)):
                    if fname.endswith(".json"):
                        fpath = os.path.join(out_dir, fname)
                        with open(fpath, "r") as f:
                            block_results.append(json.load(f))

        return jsonify({"ok": True, "blocks": block_results})
    except Exception as e:
        return jsonify(error_response("BLOCK_PARSE_ERROR", str(e))), 400
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=False)
