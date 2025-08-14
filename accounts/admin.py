from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import AppUser, UserProfile
from django.utils.html import format_html

# Register your models here.
class AppUserAdmin(UserAdmin):
    list_display = ("username","firstname","lastname","email","phonenumber","last_login","date_joined","is_active")
    list_editable=['is_active']
    list_display_links = ("email","firstname","lastname","username")
    readonly_fields = ("last_login","date_joined")
    ordering = ('-date_joined',)
   
    filter_horizontal = ()
    list_filter=()
    fieldsets = ()


class UserProfileAdmin(admin.ModelAdmin):
    def thumbnail(self,object):
        return format_html('<img src="{}" width="50" style="border-radius:50%">'.format(object.profile_pic.url))

    thumbnail.short_description = "Profile Picture"
    list_display = ('thumbnail',"user","city",'is_seller')


admin.site.register(AppUser, AppUserAdmin)

admin.site.register(UserProfile, UserProfileAdmin)

