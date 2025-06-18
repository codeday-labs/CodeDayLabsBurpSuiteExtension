from django.contrib import admin
from .models import SupabaseListing

@admin.register(SupabaseListing)
class SupabaseListingAdmin(admin.ModelAdmin):
    list_display = [field.name for field in SupabaseListing._meta.fields]
