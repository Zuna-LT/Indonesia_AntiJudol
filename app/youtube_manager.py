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
        response = request.execute()
        
        videos = []
        for item in response.get("items", []):
            video_id = item["id"]["videoId"]
            title = item["snippet"]["title"]
            videos.append((title, video_id))
            
        return videos
    
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
                    f"[{top_comment['snippet']['authorDisplayName']}] {top_comment['snippet']['textDisplay']}"
                ))
            
            next_page_token = response.get("nextPageToken")
            if not next_page_token:
                break
                
        return comments
        
    def delete_comments(self, comment_ids):
        """Delete comments by their IDs
        
        Args:
            comment_ids (list): List of comment IDs to delete
            
        Returns:
            int: Number of successfully deleted comments
        """
        success_count = 0
        for comment_id in comment_ids:
            try:
                self.youtube.comments().delete(id=comment_id).execute()
                success_count += 1
            except Exception as e:
                print(f"Failed to delete comment {comment_id}: {str(e)}")
                
        return success_count
