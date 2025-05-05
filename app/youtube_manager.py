class YouTubeManager:
    def __init__(self, youtube):
        self.youtube = youtube
        
    def fetch_videos(self, channel_id):
        request = self.youtube.search().list(
            part="snippet",
            channelId=channel_id,
            maxResults=10,
            order="date",
            type="video"
        )
        return request.execute()
    
    def fetch_comments(self, video_id):
        comments = []
        next_page_token = None
        
        while True:
            request = self.youtube.commentThreads().list(
                part="snippet",
                videoId=video_id,
                maxResults=100,
                textFormat="plainText",
                pageToken=next_page_token
            )
            response = request.execute()
            
            for item in response["items"]:
                top_comment = item["snippet"]["topLevelComment"]
                comments.append((
                    top_comment["id"],
                    top_comment["snippet"]["textDisplay"],
                    f"[{top_comment['snippet']['authorDisplayName']} {top_comment['snippet']['textDisplay']}"
                ))
            
            next_page_token = response.get("nextPageToken")
            if not next_page_token:
                break
                
        return comments