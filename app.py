import os
import secrets
from flask import Flask, jsonify #, request
from flask_smorest import Api
from flask_jwt_extended import JWTManager

from db import db
import models
from resources.item import blp as ItemBlueprint
from resources.store import blp as StoreBlueprint
from resources.tag import blp as TagBlueprint
from resources.user import blp as UserBlueprint
from blocklist import BLOCKLIST

# from flask_smorest import abort
# from db import items, stores
def create_app(db_url=None):
    app = Flask(__name__)

    # @app.get("/store")
    # def get_stores():
    #     return {"stores": list(stores.values())}

    # @app.post("/store")
    # def create_store():
    #     store_data= request.get_json()
    #     if "name" not in store_data:
    #         abort(400, message="There's no name key in the json payload.")
    #     for store in stores.values():
    #         if store_data["name"] == store["name"]:
    #             abort(400, message="Store already exists.")
    #     store_id = uuid.uuid4().hex
    #     store = {**store_data, "id":store_id}
    #     stores[store_id] = store
    #     return store, 201

    # @app.get("/item")
    # def get_all_items():
    #      return {"items": list(items.values())}

    # @app.post("/item")
    # def create_item():
    #         item_data = request.get_json()
    #         if(
    #             "price" not in item_data
    #             or "store_id" not in item_data
    #             or "name" not in item_data
    #         ):
    #             abort(400, message="Bad request. Name, store_id or name not included in the json payload.")
            
    #         for item in items.values():
    #             if(
    #                 item_data["name"] == item["name"]
    #                 and item_data["store_id"] == item["store_id"]
    #             ):
    #                 abort(400, message="Item already exists")

    #         if item_data["store_id"] not in stores:
    #             return abort(404, message="Store not found")
            
    #         item_id = uuid.uuid4().hex
    #         item = {**item_data, "id":item_id}
    #         items[item_id] = item
    #         return item, 201

    # @app.get("/store/<string:store_id>")
    # def get_store(store_id):
    #     try:
    #         return stores[store_id]
    #     except KeyError:
    #         return abort(404, message="Store not found")
        
    # @app.delete("/item/<string:store_id>")
    # def delete_store(store_id):
    #     try:
    #         del stores[store_id]
    #         return {"Message": "Store deleted."}
    #     except KeyError:
    #         return abort(404, message="Store not found")

    # @app.get("/item/<string:item_id>")
    # def get_item(item_id):
    #     try:
    #         return items[item_id]
    #     except KeyError:
    #         return abort(404, message="Item not found")

    # @app.delete("/item/<string:item_id>")
    # def delete_item(item_id):
    #     try:
    #         del items[item_id]
    #         return {"Message": "Item deleted."}
    #     except KeyError:
    #         return abort(404, message="Item not found")

    # @app.put("/item/<string:item_id>")
    # def update_item(item_id):
    #     item_data=request.get_json()
    #     if "price" not in item_data or "name" not in item_data:
    #         abort(400, message="Bad request. Ensure to have name or price in the json")
    #     try:
    #         items[item_id] |= item_data
    #         return items[item_id]
    #     except KeyError:
    #         abort(404, message="Item not found")

    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Store REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL","sqlite:///data.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    api = Api(app)

    app.config["JWT_SECRET_KEY"] = 'jose' #secrets.SystemRandom().getrandbits(128)
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload["jti"] in BLOCKLIST
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (
            jsonify(
                {"description":"The token has been revoked", "error":"token_revoked"}
            ),
            401,
        )
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return(
            jsonify(
                {
                    "description" : "The token is not fresh",
                    "error":"fresh token required"
                }
            ),
            401
        )

    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        if identity == 1:
            return {"is_admin": True}
        return {"is_admin": False}

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return(
            jsonify({"message": "The token has expired", "error":"token expired"}),
            401,
        )
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return(
            jsonify(
            {"message":"Signature verification failed.", "error":"invalid_token"}
            ),
            401,
        )
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return(
            jsonify(
                {
                    "description": "Request does not contain an access token.",
                    "error": "authorization_required",
                }
            ),
            401
        )

    with app.app_context():
        db.create_all()

    api.register_blueprint(ItemBlueprint)
    api.register_blueprint(StoreBlueprint)
    api.register_blueprint(TagBlueprint)
    api.register_blueprint(UserBlueprint)

    return app
