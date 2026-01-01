#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema()
recipe_schema = RecipeSchema(many=True)
recipe_schema_single = RecipeSchema()

class Signup(Resource):
    def post(self):
        try:
            data = request.get_json()
            
            # Create new user
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            
            # Set password (this will hash it via the setter)
            user.password_hash = data.get('password')
            
            # Add and commit to database
            db.session.add(user)
            db.session.commit()
            
            # Store user_id in session
            session['user_id'] = user.id
            
            # Return serialized user data
            return user_schema.dump(user), 201
            
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {'error': str(e)}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            if user:
                return user_schema.dump(user), 200
        
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Find user by username
        user = User.query.filter(User.username == username).first()
        
        # Authenticate user
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user_schema.dump(user), 200
        
        # Invalid credentials
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        
        if user_id:
            session.pop('user_id', None)
            return '', 204
        
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        
        # Get all recipes
        recipes = Recipe.query.all()
        
        # Serialize recipes with nested user objects
        return recipe_schema.dump(recipes), 200
    
    def post(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        
        try:
            data = request.get_json()
            
            # Get the logged-in user
            user = User.query.filter(User.id == user_id).first()
            
            if not user:
                return {'error': 'Unauthorized'}, 401
            
            # Create new recipe
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete')
            )
            
            # Associate recipe with logged-in user
            recipe.user = user
            
            # Add and commit to database
            db.session.add(recipe)
            db.session.commit()
            
            # Return serialized recipe with nested user object
            return recipe_schema_single.dump(recipe), 201
            
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {'error': str(e)}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)