# app.py

from flask import request, jsonify, session, flash, redirect, url_for
from init import app, db # Import app and db from init.py
from models import User,Sponsor,Influencer,Campaign,AdRequest,FlaggedUser,PayInfo  # Import User and other models from models.py
from werkzeug.security import check_password_hash
from flask_cors import CORS
from functools import wraps
from datetime import timedelta, datetime
import jwt
import os
SECRET_KEY = 'Y0GWd3qguSb4Jdbzo2pQmS7thiklShvv'
CORS(app, supports_credentials=True)
app.permanent_session_lifetime = timedelta(minutes=30)

# Login route - API endpoint for Vue.js login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Validate the user
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        # Set up session for server-side authentication
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session.permanent = True  # Ensure session persists between requests

        # Generate a JWT token for stateless client-side authentication
        token = jwt.encode({
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'exp': datetime.utcnow() + timedelta(hours=24)  # Token valid for 24 hours
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({'message': 'Login successful', 'token': token, 'role': user.role}), 200

    # If credentials are invalid
    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role')

    # Validate the role
    if role not in ['sponsor', 'influencer', 'admin']:
        return jsonify({'message': 'Invalid role selected'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400

    # Create and save the new user
    new_user = User(username=username, email=email, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    # Optionally create sponsor, influencer, or admin-related records
    if role == 'sponsor':
        sponsor = Sponsor(id=new_user.id)
        db.session.add(sponsor)
    elif role == 'influencer':
        influencer = Influencer(id=new_user.id)
        db.session.add(influencer)
    db.session.commit()

    return jsonify({'message': 'Account created successfully!'}), 201

@app.route('/validate_token', methods=['POST'])
def validate_token():
    data = request.json
    token = data.get('token')

    if not token:
        return jsonify({'valid': False, 'message': 'Token is missing'}), 400

    try:
        # Decode the token with the same secret key and algorithm
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({'valid': True, 'role': decoded.get('role')}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'message': 'Invalid token'}), 401



@app.route('/influencer/profile', methods=['GET'])
def get_influencer_profile():
    user_id = session.get('user_id')  # Retrieve user ID from session
    if not user_id:
        return jsonify({"error": "User not logged in"}), 401  # Return 401 if session is missing

    influencer = Influencer.query.filter_by(id=user_id).first()  # Adjust query based on your model
    if influencer:
        return jsonify({
            "username": influencer.user.username,  # Access through user relationship
            "email": influencer.user.email,        # Access through user relationship
            "category": influencer.category,
            "niche": influencer.niche,
            "followerCount": influencer.reach
        })
    else:
        return jsonify({"error": "Profile not found"}), 404



@app.route('/influencer/profile', methods=['POST'])
def update_influencer_profile():
    data = request.json
    user_id = session.get('user_id')
    influencer = Influencer.query.get(user_id)
    
    if not influencer:
        return jsonify({"error": "Influencer profile not found"}), 404
    
    # Update User fields
    user = influencer.user  # Access the related User record
    user.username = data.get('username')
    user.email = data.get('email')

    # Update Influencer-specific fields
    influencer.category = data.get('category')
    influencer.niche = data.get('niche')
    influencer.reach = data.get('reach')

    # Commit all changes to both User and Influencer tables
    db.session.commit()
    return jsonify({"message": "Profile updated successfully"})


NICHES = [
    'Technology',
    'Fashion',
    'Food',
    'Travel',
    'Lifestyle',
    'Fitness',
    'Gaming',
    'Education',
    'Business',
    'Entertainment'
]


@app.route('/niches', methods=['GET'])
def get_niches():
    return jsonify(NICHES), 200

@app.route('/sponsor/profile', methods=['GET'])
def get_sponsor_profile():
    user_id = session.get('user_id')
    sponsor = Sponsor.query.filter_by(id=user_id).first()
    if sponsor:
        return jsonify({
            "username": sponsor.user.username,
            "email": sponsor.user.email,
            "company_name": sponsor.company_name,
            "industry": sponsor.industry,
            "budget": sponsor.budget,
        })
    else:
        return jsonify({"error": "Sponsor profile not found"}), 404

@app.route('/sponsor/profile', methods=['POST'])
def update_sponsor_profile():
    data = request.json
    user_id = session.get('user_id')
    sponsor = Sponsor.query.filter_by(id=user_id).first()
    if not sponsor:
        return jsonify({"error": "Sponsor profile not found"}), 404

    # Update user details
    sponsor.user.username = data.get('username')
    sponsor.user.email = data.get('email')
    sponsor.company_name = data.get('company_name')
    sponsor.industry = data.get('industry')
    sponsor.budget = data.get('budget')
    
    db.session.commit()
    return jsonify({"message": "Profile updated successfully"})

@app.route('/manage_campaigns', methods=['GET'])
def manage_campaigns():
    sponsor_id = session.get('user_id')
    today = datetime.today().date()

    ongoing_campaigns = Campaign.query.filter(
        Campaign.end_date >= today, Campaign.flag != True, Campaign.sponsor_id == sponsor_id
    ).all()
    flagged_campaigns = Campaign.query.filter(
        Campaign.flag == True, Campaign.sponsor_id == sponsor_id
    ).all()
    past_campaigns = Campaign.query.filter(
        Campaign.end_date < today, Campaign.sponsor_id == sponsor_id
    ).all()

    ongoing_with_counts = [{"id": c.id, "name": c.name, "adRequestCount": AdRequest.query.filter_by(campaign_id=c.id).count()} for c in ongoing_campaigns]

    return jsonify({
        "ongoing": ongoing_with_counts,
        "flagged": [{"id": c.id, "name": c.name} for c in flagged_campaigns],
        "past": [{"id": c.id, "name": c.name} for c in past_campaigns]
    })


@app.route('/create_campaign', methods=['POST'])
def create_campaign():
    data = request.json
    new_campaign = Campaign(
        name=data['name'],
        description=data['description'],
        start_date=datetime.strptime(data['start_date'], '%Y-%m-%d').date(),
        end_date=datetime.strptime(data['end_date'], '%Y-%m-%d').date(),
        budget=data['budget'],
        visibility=data['visibility'],
        goals=data['goals'],
        niche=data['niche'],
        sponsor_id=session['user_id']
    )
    db.session.add(new_campaign)
    db.session.commit()
    return jsonify({"message": "Campaign created successfully"})

@app.route('/delete_campaign/<int:campaign_id>', methods=['DELETE'])
def delete_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    db.session.delete(campaign)
    db.session.commit()
    return jsonify({"message": "Campaign deleted successfully"})

@app.route('/campaign/<int:campaign_id>', methods=['GET'])
def get_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    return jsonify({
        "id": campaign.id,
        "name": campaign.name,
        "description": campaign.description,
        "start_date": campaign.start_date.isoformat(),
        "end_date": campaign.end_date.isoformat(),
        "budget": campaign.budget,
        "visibility": campaign.visibility,
        "goals": campaign.goals,
        "niche": campaign.niche,
    })

@app.route('/campaign/<int:campaign_id>', methods=['PUT'])
def update_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    data = request.json

    campaign.name = data['name']
    campaign.description = data['description']
    campaign.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
    campaign.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
    campaign.budget = data['budget']
    campaign.visibility = data['visibility']
    campaign.goals = data['goals']
    campaign.niche = data['niche']

    db.session.commit()
    return jsonify({"message": "Campaign updated successfully"})




if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
