from flask import Flask
from .dns_checker import app as dns_checker_app
from .ssl_inspector import app as ssl_inspector_app
from .domain_info import app as domain_info_app
from .ip_info import app as ip_info_app
from .analyzer import app as analyzer_app

def create_app():
    app = Flask(__name__)

    # Register blueprints
    app.register_blueprint(dns_checker_app, url_prefix='/dns')
    app.register_blueprint(ssl_inspector_app, url_prefix='/ssl')
    app.register_blueprint(domain_info_app, url_prefix='/domain')
    app.register_blueprint(ip_info_app, url_prefix='/ip')
    app.register_blueprint(analyzer_app, url_prefix='/analyze')

    return app
