from models import SwapRequest, User
from sqlalchemy import or_, inspect

def get_swap_status(current_user_id, other_user_id):
    """
    Returns:
        'none': no swap request exists
        'requested': a pending swap request exists between current_user and other_user
        'done': an accepted swap exists between current_user and other_user
    """
    try:
        # Try to query with all columns
        swap = SwapRequest.query.filter(
            or_(
                (SwapRequest.from_user_id==current_user_id) & (SwapRequest.to_user_id==other_user_id),
                (SwapRequest.from_user_id==other_user_id) & (SwapRequest.to_user_id==current_user_id)
            )
        ).order_by(SwapRequest.created_at.desc()).first()
    except:
        # If there's an error (likely due to missing message column), try again without message
        swap = SwapRequest.query.with_entities(
            SwapRequest.id,
            SwapRequest.from_user_id,
            SwapRequest.to_user_id,
            SwapRequest.skill_offered,
            SwapRequest.skill_wanted,
            SwapRequest.status,
            SwapRequest.created_at
        ).filter(
            or_(
                (SwapRequest.from_user_id==current_user_id) & (SwapRequest.to_user_id==other_user_id),
                (SwapRequest.from_user_id==other_user_id) & (SwapRequest.to_user_id==current_user_id)
            )
        ).order_by(SwapRequest.created_at.desc()).first()
    
    if not swap:
        return 'none'
    if swap.status == 'accepted':
        return 'done'
    if swap.status == 'pending':
        return 'requested'
    return 'none'

def can_request_swap(current_user_id, other_user_id):
    status = get_swap_status(current_user_id, other_user_id)
    return status == 'none'
