from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import Session
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from io import BytesIO
from PIL import Image
from PIL import ImageOps
import mysql.connector
import io
import os
import hashlib
import random
import requests
import string
from flask_mail import Mail, Message
import os
from datetime import datetime, timedelta
import zipfile
#from flask_socketio import SocketIO, emit
import json
from datetime import timedelta
import tempfile
import shutil
import psutil
import time
from collections import deque
from datetime import datetime
import re


from utils.sms_utils import send_sms, generate_otp, send_otp_via_sms
from utils.system_monitor import SystemMonitor
from utils.notification_utils import (
    get_user_notifications, 
    get_unread_notification_count, 
    notify_file_received, 
    mark_notification_as_read,
    mark_all_notifications_as_read,
    check_expiring_files,
    get_notification_icon,
    get_admin_inquiry_notifications,
    get_unread_admin_inquiry_count,
    mark_inquiry_as_read,
    mark_all_inquiries_as_read
)
from utils.file_stats import get_user_upload_stats, get_user_file_stats
from flask_socketio import SocketIO, emit, join_room, leave_room