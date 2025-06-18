from rest_framework import serializers
from .models import SupabaseListing  # or whatever your model is named

class SupabaseListingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupabaseListing
        fields = '__all__'  # ✅ This includes all fields from your model
