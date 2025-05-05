import re

def extract_channel_id(input_str):
    """Extract YouTube channel ID from various URL formats or direct channel ID
    
    Args:
        input_str (str): YouTube channel URL or ID
        
    Returns:
        str: Channel ID or None if not found
    """
    # Clean the input string
    input_str = input_str.strip()
    
    # Direct channel ID pattern (UC...)
    if re.match(r'^UC[\w-]{22}$', input_str):
        return input_str
        
    # Channel URL patterns
    patterns = [
        # /channel/ format
        r'youtube\.com/channel/(UC[\w-]{22})',
        # /c/ format - requires additional API call to resolve
        r'youtube\.com/c/([a-zA-Z0-9_-]+)',
        # /user/ format - requires additional API call to resolve
        r'youtube\.com/user/([a-zA-Z0-9_-]+)',
        # /@ format
        r'youtube\.com/@([a-zA-Z0-9_-]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, input_str)
        if match:
            result = match.group(1)
            # If it's already a channel ID format, return it directly
            if result.startswith('UC') and len(result) == 24:
                return result
            # For other formats, we should ideally make an API call here
            # but for now just return the username/handle
            return result
            
    return None
