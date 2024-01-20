from rest_framework.renderers import JSONRenderer
from task_manager import settings

class AbsoluteURLRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        request = renderer_context.get('request')

        if request:
            self.update_media_urls(data, request)

        return super().render(data, accepted_media_type, renderer_context)
    
    def update_media_urls(self, data, request):
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and value.startswith('/media/'):
                    data[key] = settings.MEDIA_BASE_URL+value
                elif isinstance(value, (dict, list)):
                    self.update_media_urls(value, request)

        elif isinstance(data, list):
            for item in data:
                self.update_media_urls(item, request)
