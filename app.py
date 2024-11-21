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

@app.route('/campaign/<int:campaign_id>/requests', methods=['GET'])
def view_requests(campaign_id):
    sponsor_id = session.get('user_id')

    # Ensure the campaign exists and belongs to the sponsor
    campaign = Campaign.query.filter_by(id=campaign_id, sponsor_id=sponsor_id).first_or_404()

    # Fetch ad requests with related sender and receiver details
    ad_requests = AdRequest.query.filter_by(campaign_id=campaign_id).all()

    # Serialize data for response
    serialized_requests = [
        {
            'id': req.id,
            'sender': {
                'id': req.sender.id,
                'username': req.sender.username
            },
            'receiver': {
                'id': req.receiver.id,
                'username': req.receiver.username
            },
            'messages': req.messages,
            'requirements': req.requirements,
            'payment_amount': req.payment_amount,
            'status': req.status
        }
        for req in ad_requests
    ]

    return jsonify({
        'campaign': {
            'id': campaign.id,
            'name': campaign.name
        },
        'ad_requests': serialized_requests
    })

@app.route('/ad_request/accept/<int:request_id>', methods=['POST'])
def accept_ad_request(request_id):
    """
    Accepts an ad request if the current user is not the latest sender.
    """
    ad_request = AdRequest.query.get_or_404(request_id)

    # Ensure the current user is not the latest sender
    if ad_request.latest_sender == session['user_id']:
        return jsonify({'error': 'You cannot accept a request you last sent'}), 403

    # Ensure the user is the receiver
    if ad_request.receiver_id != session['user_id']:
        return jsonify({'error': 'You do not have permission to accept this request'}), 403

    # Mark the request as accepted
    ad_request.status = 'accepted'

    # Create payment info
    new_payinfo = PayInfo(
        campaign_id=ad_request.campaign_id,
        influencer_id=ad_request.influencer_id,
        status='pending',
        amount=ad_request.payment_amount
    )

    db.session.add(new_payinfo)
    db.session.commit()

    return jsonify({'message': 'Ad request accepted successfully'})




@app.route('/ad_request/reject/<int:request_id>', methods=['POST'])
def reject_ad_request(request_id):
    """
    Rejects an ad request if the current user is not the latest sender.
    """
    ad_request = AdRequest.query.get_or_404(request_id)

    # Ensure the current user is not the latest sender
    if ad_request.latest_sender == session['user_id']:
        return jsonify({'error': 'You cannot reject a request you last sent'}), 403

    # Ensure the user is the receiver
    if ad_request.receiver_id != session['user_id']:
        return jsonify({'error': 'You do not have permission to reject this request'}), 403

    # Mark the request as rejected
    ad_request.status = 'rejected'
    db.session.commit()

    return jsonify({'message': 'Ad request rejected successfully'})





@app.route('/ad_request/modify/<int:request_id>', methods=['POST'])
def modify_ad_request(request_id):
    """
    Endpoint to modify an existing ad request.
    """
    from models import AdRequest

    data = request.json

    # Fetch the ad request
    ad_request = AdRequest.query.get_or_404(request_id)

    # Update fields if present in the request
    if 'messages' in data:
        ad_request.messages = data['messages']
    if 'requirements' in data:
        ad_request.requirements = data['requirements']
    if 'payment_amount' in data:
        ad_request.payment_amount = float(data['payment_amount'])

    try:
        db.session.commit()
        return jsonify({'message': 'Ad request modified successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500




@app.route('/ad_request/delete/<int:request_id>', methods=['POST'])
def delete_ad_request(request_id):
    ad_request = AdRequest.query.get_or_404(request_id)

    # Ensure the sponsor owns the associated campaign
    campaign = Campaign.query.get(ad_request.campaign_id)
    if campaign.sponsor_id != session['user_id']:
        return jsonify({'error': 'Unauthorized action'}), 403

    if ad_request.status in ['accepted', 'rejected']:
        return jsonify({'error': 'Cannot delete an accepted or rejected request'}), 400

    db.session.delete(ad_request)
    db.session.commit()

    return jsonify({'message': 'Ad request deleted successfully'})


@app.route('/influencers', methods=['GET'])
def list_influencers():
    search_term = request.args.get('search', '')
    selected_niche = request.args.get('niche', 'all')
    sort_by = request.args.get('sort_by', 'desc')

    query = Influencer.query.filter(Influencer.flag != True)  # Exclude flagged influencers

    # Apply filters
    if selected_niche != 'all':
        query = query.filter_by(niche=selected_niche)

    if search_term:
        query = query.join(User).filter(
            (User.username.ilike(f'%{search_term}%')) |
            (Influencer.category.ilike(f'%{search_term}%')) |
            (Influencer.niche.ilike(f'%{search_term}%'))
        )

    # Apply sorting
    if sort_by == 'asc':
        query = query.order_by(Influencer.reach.asc())
    else:
        query = query.order_by(Influencer.reach.desc())

    # Fetch results
    influencers = query.all()

    # Serialize response
    serialized_influencers = [
        {
            'id': inf.id,
            'username': inf.user.username,
            'category': inf.category,
            'niche': inf.niche,
            'reach': inf.reach
        }
        for inf in influencers
    ]

    return jsonify({'influencers': serialized_influencers})

@app.route('/sponsor/campaigns', methods=['GET'])
def get_sponsor_campaigns():
    sponsor_id = session.get('user_id')
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor_id).all()

    serialized_campaigns = [
        {'id': campaign.id, 'name': campaign.name}
        for campaign in campaigns
    ]

    return jsonify({'campaigns': serialized_campaigns})

@app.route('/influencer/<int:influencer_id>', methods=['GET'])
def get_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)

    return jsonify({
        'id': influencer.id,
        'username': influencer.user.username,
        'category': influencer.category,
        'niche': influencer.niche,
        'reach': influencer.reach,
    })

@app.route('/ad_request/<int:influencer_id>', methods=['POST'])
def submit_ad_request(influencer_id):
    """
    Endpoint to create a new ad request for a specified influencer.
    """
    from models import AdRequest, Campaign, Influencer  # Ensure proper model imports

    data = request.json
    sender_id = session.get('user_id')  # Assume sponsor is logged in

    # Ensure required fields are present in the request
    required_fields = ['campaign_id', 'messages', 'requirements', 'payment_amount']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Validate campaign ownership
    campaign = Campaign.query.filter_by(id=data['campaign_id'], sponsor_id=sender_id).first()
    if not campaign:
        return jsonify({'error': 'Invalid campaign or unauthorized access'}), 403

    # Validate the influencer exists
    influencer = Influencer.query.get_or_404(influencer_id)

    # Ensure no duplicate request exists
    existing_request = AdRequest.query.filter_by(
        campaign_id=data['campaign_id'],
        influencer_id=influencer_id
    ).first()
    if existing_request:
        return jsonify({'error': 'An ad request for this influencer and campaign already exists'}), 400

    # Create the new ad request
    try:
        new_request = AdRequest(
            campaign_id=data['campaign_id'],
            influencer_id=influencer_id,
            sender_id=sender_id,
            receiver_id=influencer_id,  # Set the influencer as the receiver
            messages=data['messages'],
            requirements=data['requirements'],
            payment_amount=float(data['payment_amount']),
            status='pending',  # Default status
            latest_sender=sender_id,
        )

        db.session.add(new_request)
        db.session.commit()

        return jsonify({'message': 'Ad request submitted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/sponsor/ad_requests', methods=['GET'])
def sponsor_ad_requests():
    """
    Endpoint to fetch ad requests categorized as ongoing, expired, and flagged
    for a sponsor.
    """
    from models import AdRequest, Campaign, Influencer  # Ensure correct imports
    from datetime import datetime

    sponsor_id = session.get('user_id')  # Fetch logged-in sponsor ID
    if not sponsor_id:
        return jsonify({'error': 'Unauthorized access'}), 401

    # Current date for filtering
    today = datetime.today()

    # Ongoing ad requests (not expired and associated with active campaigns)
    ongoing_requests = AdRequest.query.join(Campaign).join(Influencer).filter(
        Campaign.sponsor_id == sponsor_id,
        Campaign.end_date >= today,
        Campaign.flag == False,
        (AdRequest.sender_id == sponsor_id) | (AdRequest.receiver_id == sponsor_id)
    ).all()

    # Expired ad requests (campaign has ended)
    expired_requests = AdRequest.query.join(Campaign).filter(
        Campaign.sponsor_id == sponsor_id,
        Campaign.end_date < today,
    ).all()

    # Flagged ad requests (associated with flagged influencers)
    flagged_requests = AdRequest.query.join(Campaign).join(Influencer).filter(
        Campaign.sponsor_id == sponsor_id,
        Influencer.flag == True,
        Campaign.end_date >= today,
        (AdRequest.sender_id == sponsor_id) | (AdRequest.receiver_id == sponsor_id)
    ).all()

    # Serialize data for response
    def serialize_request(ad_request):
        return {
        'id': ad_request.id,
        'campaign': {'id': ad_request.campaign.id, 'name': ad_request.campaign.name},
        'influencer': {'id': ad_request.influencer.id, 'username': ad_request.influencer.user.username},
        'messages': ad_request.messages,
        'requirements': ad_request.requirements,
        'payment_amount': ad_request.payment_amount,
        'status': ad_request.status,
        'latest_sender': ad_request.latest_sender,  # Include the latest_sender field
    }


    response = {
        'ongoing': [serialize_request(req) for req in ongoing_requests],
        'expired': [serialize_request(req) for req in expired_requests],
        'flagged': [serialize_request(req) for req in flagged_requests],
    }

    return jsonify(response), 200

@app.route('/sponsor/payments', methods=['GET'])
def get_sponsor_payments():
    """
    Fetch all pending and paid payments for the sponsor.
    """
    sponsor_id = session.get('user_id')  # Ensure the sponsor is logged in
    if not sponsor_id:
        return jsonify({'error': 'Unauthorized access'}), 401

    # Fetch payments related to the sponsor's campaigns
    payments = PayInfo.query.join(Campaign).filter(
        Campaign.sponsor_id == sponsor_id
    ).all()

    # Serialize response
    serialized_payments = [
        {
            'id': payment.id,
            'campaign': {'id': payment.campaign_id, 'name': payment.campaign.name},
            'influencer': {'id': payment.influencer_id, 'username': payment.influencer.user.username},
            'amount': payment.amount,
            'status': payment.status,
        }
        for payment in payments
    ]

    return jsonify({'payments': serialized_payments})

@app.route('/sponsor/payment/<int:payment_id>', methods=['POST'])
def pay_payment(payment_id):
    """
    Mark a specific payment as 'paid'.
    """
    sponsor_id = session.get('user_id')  # Ensure the sponsor is logged in
    if not sponsor_id:
        return jsonify({'error': 'Unauthorized access'}), 401

    payment = PayInfo.query.get_or_404(payment_id)

    # Verify that the payment is related to the sponsor
    if payment.campaign.sponsor_id != sponsor_id:
        return jsonify({'error': 'Unauthorized action'}), 403

    # Mark the payment as paid
    payment.status = 'paid'
    db.session.commit()

    return jsonify({'message': 'Payment successfully processed'})


if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
