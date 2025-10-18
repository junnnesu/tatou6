import os
import io
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle


import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod

"""
Complete RMAP Implementation for Group 6
"""
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP
import base64
import secrets
import json

def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    
    # --- Initialize security monitoring ---
    from security_log_config import setup_security_logging
    from security_monitor import init_security_monitoring
    
    # Setup security logging
    app.security_logger = setup_security_logging()
    
    # Initialize security monitoring middleware
    init_security_monitoring(app)

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    
    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # --- Routes ---
    
    @app.route("/<path:filename>")
    def static_files(filename):
        # Fix CWE-22: Restrict accessible static file types to prevent flag file leakage
        allowed_extensions = {'.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg'}
        allowed_files = {'index.html', 'login.html', 'signup.html', 'documents.html', 'style.css'}
        
        # 1. Check path length
        if len(filename) > 255:
            return jsonify({"error": "filename too long"}), 400
        
        # 2. Check for dangerous characters
        if any(char in filename for char in ['..', '~', '$', '`', '|', '&', ';']):
            return jsonify({"error": "invalid characters in filename"}), 400
        
        # 3. Normalize path
        try:
            file_path = Path(filename).resolve()
        except Exception:
            return jsonify({"error": "invalid path"}), 400
        
        # 4. Check file extension and name
        if file_path.suffix.lower() not in allowed_extensions:
            return jsonify({"error": "file type not allowed"}), 403
        
        if file_path.name not in allowed_files:
            return jsonify({"error": "file not found"}), 404
        
        # 5. Prevent flag file access - emergency protection
        if any(keyword in filename.lower() for keyword in ['flag', 'secret', 'password', 'key', 'token', 'credential']):
            return jsonify({"error": "file not found"}), 404
        
        # 6. Check for symbolic links
        try:
            if file_path.is_symlink():
                return jsonify({"error": "symbolic links not allowed"}), 403
        except Exception:
            return jsonify({"error": "file not found"}), 404
        
        # 7. Final cleanup using secure_filename
        filename = secure_filename(filename)
        if not filename:
            return jsonify({"error": "invalid filename"}), 400
        
        try:
            return app.send_static_file(filename)
        except FileNotFoundError:
            return jsonify({"error": "file not found"}), 404

    @app.route("/")
    def home():
        return app.send_static_file("index.html")
    
    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        # Validate login to prevent injection attacks - Fix: Allow Mr_Important user registration
        # Special handling: Allow Mr_Important user registration
        if login.lower() in ['mr_important', 'mrimportant', 'mr-important']:
            # Allow Mr_Important user registration but perform basic security checks
            if any(char in login for char in [' ', '\t', '\n', '\r', ';', '&', '|', '`', '$', '(', ')', '[', ']', '{', '}', '<', '>', '?', '!', '@', '#', '%', '^', '*', '+', '=', '~', '\\', '/', ':', '"', "'"]):
                return jsonify({"error": "login contains invalid characters"}), 400
        else:
            # Standard validation for other users
            if not login.replace("_", "").replace("-", "").isalnum():
                return jsonify({"error": "login must contain only alphanumeric characters, underscores, and hyphens"}), 400
            
            # Additional check: prevent dangerous characters
            if any(char in login for char in [' ', '\t', '\n', '\r', ';', '&', '|', '`', '$', '(', ')', '[', ']', '{', '}', '<', '>', '?', '!', '@', '#', '%', '^', '*', '+', '=', '~', '\\', '/', ':', '"', "'"]):
                return jsonify({"error": "login contains invalid characters"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {email, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        fname = secure_filename(file.filename)
        if not fname:
            return jsonify({"error": "invalid filename"}), 400
        
        # file extension validation
        if not fname.lower().endswith('.pdf'):
            return jsonify({"error": "only PDF files are allowed"}), 400

        # MIME type validation
        allowed_mime_types = ['application/pdf', 'application/x-pdf']
        if file.content_type not in allowed_mime_types:
            return jsonify({"error": f"invalid file type: {file.content_type}, must be PDF"}), 400
        
        # file content validation (basic check for PDF header)
        file_header = file.stream.read(5)
        file.stream.seek(0)  # reset stream position

        if not file_header.startswith(b'%PDF-'):
            return jsonify({"error": "file is not a valid PDF (invalid magic number)"}), 400



        user_dir = app.config["STORAGE_DIR"] / "files" / secure_filename(g.user["login"])
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200

    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.id = :uid AND d.id = :did
                    """),
                    {"uid": int(g.user["id"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.id = :uid
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don't leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        # Use the safe path resolution helper
        try:
            file_path = _safe_resolve_under_storage(row.path, app.config["STORAGE_DIR"])
        except RuntimeError:
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp
    
    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        # Sanitize link parameter
        link = secure_filename(link)
        if not link:
            return jsonify({"error": "invalid link"}), 400
        
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don't leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        # Use the safe path resolution helper
        try:
            file_path = _safe_resolve_under_storage(row.path, app.config["STORAGE_DIR"])
        except RuntimeError:
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # DELETE /api/delete-document  (and variants) - FIXED SQL INJECTION
    @app.route("/api/delete-document", methods=["DELETE", "POST"])
    @app.route("/api/delete-document/<int:document_id>", methods=["DELETE"])
    @require_auth  # Added authentication requirement
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if document_id is None:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership) - FIXED SQL INJECTION
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT * FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": doc_id, "uid": int(g.user["id"])}
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            # Don't reveal others' docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,
        }), 200
        
    # POST /api/create-watermark or /api/create-watermark/<id>
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
            
        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership - FIXED to check ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        try:
            file_path = _safe_resolve_under_storage(row.path, app.config["STORAGE_DIR"])
        except RuntimeError:
            return jsonify({"error": "document path invalid"}), 500
            
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # link token = sha1(watermarked_file_name)
        link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(dest_path)
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201
        
    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        """
        Load a serialized Python class implementing WatermarkingMethod.
        SECURITY: This is inherently dangerous - pickle/dill can execute arbitrary code.
        Consider disabling this in production or implementing strict validation.
        """
        payload = request.get_json(silent=True) or {}
        filename = (payload.get("filename") or "").strip()
        filename = secure_filename(filename)  # Sanitize filename
        overwrite = bool(payload.get("overwrite", False))

        if not filename:
            return jsonify({"error": "filename is required"}), 400

        # Only allow specific file extensions
        if not filename.endswith(('.pkl', '.dill')):
            return jsonify({"error": "only .pkl or .dill files are allowed"}), 400

        # Locate the plugin - restrict to user's own plugin directory
        storage_root = Path(app.config["STORAGE_DIR"])
        user_login = secure_filename(g.user["login"])
        plugins_dir = storage_root / "files" / user_login / "plugins"
        
        try:
            plugins_dir.mkdir(parents=True, exist_ok=True)
            plugin_path = _safe_resolve_under_storage(plugins_dir / filename, storage_root)
        except Exception as e:
            return jsonify({"error": f"plugin path error: {e}"}), 500

        if not plugin_path.exists():
            return jsonify({"error": f"plugin file not found: {filename}"}), 404

        # WARNING: Unpickling is dangerous - consider alternatives
        try:
            with plugin_path.open("rb") as f:
                obj = _pickle.load(f)
        except Exception as e:
            return jsonify({"error": f"failed to deserialize plugin: {e}"}), 400

        # Accept: class object, or instance
        if isinstance(obj, type):
            cls = obj
        else:
            cls = obj.__class__

        # Determine method name for registry
        method_name = getattr(cls, "name", getattr(cls, "__name__", None))
        if not method_name or not isinstance(method_name, str):
            return jsonify({"error": "plugin class must define a readable name"}), 400

        # Validate interface
        has_api = all(hasattr(cls, attr) for attr in ("add_watermark", "read_secret"))
        if WatermarkingMethod is not None:
            is_ok = issubclass(cls, WatermarkingMethod) and has_api
        else:
            is_ok = has_api
        if not is_ok:
            return jsonify({"error": "plugin does not implement WatermarkingMethod API"}), 400
            
        # Register the class
        WMUtils.METHODS[method_name] = cls()
        
        return jsonify({
            "loaded": True,
            "filename": filename,
            "registered_as": method_name,
            "class_qualname": f"{getattr(cls, '__module__', '?')}.{getattr(cls, '__qualname__', cls.__name__)}",
            "methods_count": len(WMUtils.METHODS)
        }), 201
    
    # GET /api/get-watermarking-methods
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []
        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
        return jsonify({"methods": methods, "count": len(methods)}), 200
        
    # POST /api/read-watermark - FIXED to check ownership
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
            
        payload = request.get_json(silent=True) or {}
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        if not method or not isinstance(key, str):
            return jsonify({"error": "method and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        try:
            file_path = _safe_resolve_under_storage(row.path, app.config["STORAGE_DIR"])
        except RuntimeError:
            return jsonify({"error": "document path invalid"}), 500
            
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410
        
        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201

    # Initialize RMAP
    def init_rmap():
        """Initialize RMAP handler with server keys and client public keys."""
        try:
            # PKI目录就在storage/pki下
            pki_dir = app.config["STORAGE_DIR"] / "pki"
            
            # 组6的密钥
            server_priv_path = pki_dir / "g6.asc"           # 私钥
            server_pub_path = pki_dir / "Group_06.asc"      # 公钥
            
            # 验证文件存在
            if not server_priv_path.exists():
                app.logger.error(f"Server private key not found: {server_priv_path}")
                return None
                
            if not server_pub_path.exists():
                app.logger.error(f"Server public key not found: {server_pub_path}")
                return None
            
            app.logger.info(f"Loading RMAP keys from {pki_dir}")
            app.logger.info(f"  Server private key: {server_priv_path.name}")
            app.logger.info(f"  Server public key: {server_pub_path.name}")
            
            # 初始化IdentityManager
            # 它会自动加载pki_dir下所有的.asc文件作为客户端公钥
            from rmap.identity_manager import IdentityManager
            identity_manager = IdentityManager(
                client_keys_dir=str(pki_dir),
                server_public_key_path=str(server_pub_path),
                server_private_key_path=str(server_priv_path),
                server_private_key_passphrase=None  # 如果私钥有密码，在这里提供
            )
            
            # 初始化RMAP处理器
            from rmap.rmap import RMAP
            rmap_handler = RMAP(identity_manager)
            
            # 打印加载的身份（用于调试）
            loaded_identities = list(identity_manager.identity_public_keys.keys())
            app.logger.info(f"RMAP initialized successfully")
            app.logger.info(f"Loaded {len(loaded_identities)} client identities: {loaded_identities}")
            
            return rmap_handler
            
        except Exception as e:
            app.logger.error(f"Failed to initialize RMAP: {e}")
            import traceback
            app.logger.error(traceback.format_exc())
            return None

    # Initialize RMAP when app starts
    app.rmap_handler = init_rmap()
    app.rmap_sessions = {}  # Store session data

    # RMAP Routes
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        """RMAP Authentication - Message 1."""
        if not app.rmap_handler:
            return jsonify({"error": "RMAP not configured"}), 503
            
        try:
            # 获取请求数据
            incoming = request.get_json(silent=True) or {}
            
            app.logger.info(f"[RMAP-INITIATE] Received request")
            
            # RMAP库会自动处理解密、验证和加密响应
            response = app.rmap_handler.handle_message1(incoming)
            
            # 检查是否有错误
            if "error" in response:
                app.logger.error(f"[RMAP-INITIATE] Error: {response['error']}")
                return jsonify(response), 400
            
            # 成功 - response已经是正确格式: {"payload": "<encrypted>"}
            app.logger.info(f"[RMAP-INITIATE] Success")
            return jsonify(response), 200
            
        except Exception as e:
            app.logger.error(f"[RMAP-INITIATE] Exception: {e}")
            import traceback
            app.logger.error(traceback.format_exc())
            return jsonify({"error": f"Internal error: {str(e)}"}), 500

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        """RMAP Authentication - Message 2 and watermark generation."""
        if not app.rmap_handler:
            return jsonify({"error": "RMAP not configured"}), 503
            
        try:
            # 获取请求数据
            incoming = request.get_json(silent=True) or {}
            
            app.logger.info(f"[RMAP-GET-LINK] Received request")
            
            # 处理消息2
            response = app.rmap_handler.handle_message2(incoming)
            
            if "error" in response:
                app.logger.error(f"[RMAP-GET-LINK] Error: {response['error']}")
                return jsonify(response), 400
            
            # response包含 {"result": "<32-hex>"}
            link_hex = response["result"]
            app.logger.info(f"[RMAP-GET-LINK] Generated link: {link_hex}")
            
            # 找出是哪个组（identity）
            identity = None
            for ident, (nc, ns) in app.rmap_handler.nonces.items():
                combined = (nc << 64) | ns
                if f"{combined:032x}" == link_hex:
                    identity = ident
                    break
            
            if not identity:
                app.logger.error(f"[RMAP-GET-LINK] Could not find identity for link")
                return jsonify({"error": "Session not found"}), 400
            
            app.logger.info(f"[RMAP-GET-LINK] Identity: {identity}")
            
            # 检查是否已经创建过这个水印版本
            with get_engine().connect() as conn:
                existing = conn.execute(
                    text("SELECT * FROM Versions WHERE link = :link"),
                    {"link": link_hex}
                ).first()
            
            if existing:
                app.logger.info(f"[RMAP-GET-LINK] Version already exists")
                return jsonify({"result": link_hex}), 200
            
            # 需要创建新的水印PDF
            app.logger.info(f"[RMAP-GET-LINK] Creating watermarked PDF for {identity}")
            
            try:
                with get_engine().begin() as conn:
                    # 找一个文档来水印（优先flag文档）
                    doc_row = conn.execute(
                        text("""
                            SELECT d.id, d.name, d.path 
                            FROM Documents d 
                            JOIN Users u ON d.ownerid = u.id 
                            WHERE u.login LIKE '%Important%' 
                            OR d.name LIKE '%flag%'
                            ORDER BY d.id ASC
                            LIMIT 1
                        """)
                    ).first()
                    
                    if not doc_row:
                        # 如果没有flag文档，用第一个文档
                        doc_row = conn.execute(
                            text("SELECT id, name, path FROM Documents ORDER BY id ASC LIMIT 1")
                        ).first()
                    
                    if not doc_row:
                        app.logger.error(f"[RMAP-GET-LINK] No documents available")
                        return jsonify({"error": "No document available for watermarking"}), 404
                    
                    app.logger.info(f"[RMAP-GET-LINK] Using document: {doc_row.name} (ID: {doc_row.id})")
                    
                    # 解析文件路径
                    file_path = _safe_resolve_under_storage(doc_row.path, app.config["STORAGE_DIR"])
                    
                    if not file_path.exists():
                        app.logger.error(f"[RMAP-GET-LINK] Document file not found: {file_path}")
                        return jsonify({"error": "Document file not found"}), 404
                    
                    # 准备水印参数
                    secret = f"RMAP-{identity}-{link_hex[:8]}"
                    key = app.config["SECRET_KEY"] or "default-rmap-key"
                    
                    # 选择可用的水印方法
                    available_methods = list(WMUtils.METHODS.keys())
                    app.logger.info(f"[RMAP-GET-LINK] Available methods: {available_methods}")
                    
                    # 优先使用text-overlay，否则用第一个可用方法
                    if "text-overlay" in available_methods:
                        method = "text-overlay"
                    elif "toy-eof" in available_methods:
                        method = "toy-eof"
                    else:
                        method = available_methods[0]
                    
                    app.logger.info(f"[RMAP-GET-LINK] Using watermark method: {method}")
                    
                    # 应用水印
                    wm_bytes = WMUtils.apply_watermark(
                        pdf=str(file_path),
                        secret=secret,
                        key=key,
                        method=method,
                        position="diagonal"
                    )
                    
                    # 保存水印文件
                    wm_dir = app.config["STORAGE_DIR"] / "rmap_watermarks"
                    wm_dir.mkdir(parents=True, exist_ok=True)
                    wm_path = wm_dir / f"rmap_{link_hex}.pdf"
                    
                    with wm_path.open("wb") as f:
                        f.write(wm_bytes)
                    
                    app.logger.info(f"[RMAP-GET-LINK] Saved watermarked PDF: {wm_path}")
                    
                    # 存入数据库
                    conn.execute(
                        text("""
                            INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                            VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                        """),
                        {
                            "documentid": doc_row.id,
                            "link": link_hex,
                            "intended_for": identity,
                            "secret": secret,
                            "method": method,
                            "position": "diagonal",
                            "path": str(wm_path)
                        }
                    )
                    
                    app.logger.info(f"[RMAP-GET-LINK] Database entry created")
            
            except Exception as e:
                app.logger.error(f"[RMAP-GET-LINK] Failed to create watermark: {e}")
                import traceback
                app.logger.error(traceback.format_exc())
                return jsonify({"error": f"Failed to create watermarked PDF: {str(e)}"}), 500
            
            # 返回结果
            return jsonify({"result": link_hex}), 200
            
        except Exception as e:
            app.logger.error(f"[RMAP-GET-LINK] Exception: {e}")
            import traceback
            app.logger.error(traceback.format_exc())
            return jsonify({"error": f"Internal error: {str(e)}"}), 500


    return app
    

# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)