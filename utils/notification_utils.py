from datetime import datetime, timedelta
import mysql.connector
from flask import current_app
from flask_mail import Message, Mail

def get_db_connection():
    return mysql.connector.connect(
        host=current_app.config['MYSQL_HOST'],
        user=current_app.config['MYSQL_USER'],
        password=current_app.config['MYSQL_PASSWORD'],
        database=current_app.config['MYSQL_DB']
    )

def create_notification(user_id, notification_type, title, message, file_id=None, sender_username=None):
    """Create a new notification for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO notifications (user_id, type, title, message, file_id, sender_username) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, notification_type, title, message, file_id, sender_username)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error creating notification: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_user_notifications(user_id, limit=10):
    """Get notifications for a specific user"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute(
            """SELECT n.*, f.filename 
               FROM notifications n 
               LEFT JOIN files f ON n.file_id = f.id 
               WHERE n.user_id = %s 
               ORDER BY n.created_at DESC 
               LIMIT %s""",
            (user_id, limit)
        )
        notifications = cursor.fetchall()
        return notifications
    except Exception as e:
        print(f"Error fetching notifications: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

def get_unread_notification_count(user_id):
    """Get count of unread notifications for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id = %s AND is_read = 0",
            (user_id,)
        )
        count = cursor.fetchone()[0]
        return count
    except Exception as e:
        print(f"Error getting notification count: {e}")
        return 0
    finally:
        cursor.close()
        conn.close()

def mark_notification_as_read(notification_id):
    """Mark a notification as read"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE notifications SET is_read = 1 WHERE id = %s",
            (notification_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error marking notification as read: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def mark_all_notifications_as_read(user_id):
    """Mark all notifications as read for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE notifications SET is_read = 1 WHERE user_id = %s",
            (user_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error marking all notifications as read: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def notify_file_received(receiver_id, sender_username, filename, file_id):
    """Create notification when user receives a file"""
    title = "New File Received"
    message = f"@{sender_username} sent you '{filename}'"
    # Create in-app notification
    notification_created = create_notification(receiver_id, 'file_received', title, message, file_id, sender_username)
    
    # Send email notification
    try:
        # Get receiver's email from role-specific tables
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COALESCE(b.email, g.email, e.email) AS email
            FROM users u
            LEFT JOIN brgycaptain b ON u.id = b.user_id
            LEFT JOIN government_position g ON u.id = g.user_id
            LEFT JOIN employee e ON u.id = e.user_id
            WHERE u.id = %s
        """, (receiver_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result and result[0]:
            receiver_email = result[0]
            print(f"Sending email notification to {receiver_email} for file {filename}")
            send_file_received_email(receiver_email, sender_username, filename, file_id)
        else:
            print(f"No email found for user ID {receiver_id}")
    except Exception as e:
        print(f"Error sending email notification: {e}")
    
    return notification_created

def send_file_received_email(receiver_email, sender_username, filename, file_id=None):
    """Send email notification when user receives a file"""
    try:
        # Import mail instance from app instead of creating a new one
        from flask import current_app
        from flask_mail import Mail, Message
        
        # Get the mail instance from the app context
        mail = Mail(current_app._get_current_object())
        
        # Get file expiration information if file_id is provided
        expiration_info = "The file may have an expiration date. Please download it as soon as possible."
        if file_id:
            try:
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT expiration_time FROM files WHERE id = %s", (file_id,))
                file_data = cursor.fetchone()
                cursor.close()
                conn.close()
                
                if file_data and file_data['expiration_time']:
                    expiration_time = file_data['expiration_time']
                    expiration_info = f"This file will expire on: {expiration_time.strftime('%Y-%m-%d %H:%M:%S')}"
            except Exception as e:
                print(f"Error getting file expiration: {e}")
        
        subject = "FilSha: New File Received"
        body = f"""
        Hello,
        
        You have received a new file on FilSha.
        
        File: {filename}
        Sender: {sender_username}
        {expiration_info}
        
        IMPORTANT: If this file is password-protected, please contact the sender ({sender_username}) for the password.
        
        Please log in to your FilSha account to view and download the file.
        
        Thank you,
        FilSha Team
        """
        
        msg = Message(
            subject=subject,
            recipients=[receiver_email],
            body=body
        )
        
        mail.send(msg)
        print(f"Email notification sent to {receiver_email} for file {filename}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def notify_file_expiring(user_id, filename, file_id, hours_until_expiry):
    """Create notification for expiring files"""
    title = "File Expiring Soon"
    message = f"'{filename}' will be deleted in {hours_until_expiry} hours if not downloaded"
    return create_notification(user_id, 'file_expiring', title, message, file_id)

def check_expiring_files():
    """Check for files that are expiring soon and create notifications"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check for files expiring in the next 24 hours
        cursor.execute(
            """SELECT f.*, u.username as owner_username 
               FROM files f 
               JOIN users u ON f.owner_id = u.id 
               WHERE f.expiration_time IS NOT NULL 
               AND f.expiration_time BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 24 HOUR)
               AND NOT EXISTS (
                   SELECT 1 FROM notifications n 
                   WHERE n.file_id = f.id 
                   AND n.type = 'file_expiring' 
                   AND n.created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)
               )"""
        )
        expiring_files = cursor.fetchall()
        
        for file_info in expiring_files:
            # Calculate hours until expiry
            time_diff = file_info['expiration_time'] - datetime.now()
            hours_until_expiry = max(1, int(time_diff.total_seconds() / 3600))
            
            # Notify file owner
            notify_file_expiring(
                file_info['owner_id'], 
                file_info['filename'], 
                file_info['id'], 
                hours_until_expiry
            )
            
            # Notify shared users if any
            if file_info['shared_with']:
                shared_users = file_info['shared_with'].split(',')
                for shared_user in shared_users:
                    shared_user = shared_user.strip()
                    # Get user ID from username
                    cursor.execute("SELECT id FROM users WHERE username = %s", (shared_user,))
                    user_result = cursor.fetchone()
                    if user_result:
                        notify_file_expiring(
                            user_result['id'], 
                            file_info['filename'], 
                            file_info['id'], 
                            hours_until_expiry
                        )
        
        return len(expiring_files)
    except Exception as e:
        print(f"Error checking expiring files: {e}")
        return 0
    finally:
        cursor.close()
        conn.close()

def get_notification_icon(notification_type):
    """Get appropriate icon for notification type"""
    icons = {
        'file_received': 'bi bi-file-earmark-arrow-down text-success',
        'file_expiring': 'bi bi-clock text-warning',
        'file_downloaded': 'bi bi-download text-info',
        'file_shared': 'bi bi-share text-primary',
        'user_inquiry': 'bi bi-question-circle text-info',
        'inquiry_resolved': 'bi bi-check-circle text-success'
    }
    return icons.get(notification_type, 'bi bi-info-circle text-primary')


def get_admin_inquiry_notifications(limit=10):
    """Get notifications for admin about user inquiries"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute(
            """SELECT 
                ui.id, 
                ui.subject, 
                ui.description, 
                ui.status, 
                ui.created_at, 
                ui.is_read,
                u.username 
            FROM user_inquiries ui
            LEFT JOIN users u ON ui.user_id = u.id
            ORDER BY ui.created_at DESC
            LIMIT %s""",
            (limit,)
        )
        inquiries = cursor.fetchall()
        return inquiries
    except Exception as e:
        print(f"Error fetching admin inquiry notifications: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

def get_unread_admin_inquiry_count():
    """Get count of unread user inquiries for admin"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """SELECT COUNT(*) 
            FROM user_inquiries 
            WHERE status = 'Pending' AND (is_read = 0 OR is_read IS NULL)"""
        )
        count = cursor.fetchone()[0]
        return count
    except Exception as e:
        print(f"Error getting unread inquiry count: {e}")
        return 0
    finally:
        cursor.close()
        conn.close()

def mark_inquiry_as_read(inquiry_id):
    """Mark a user inquiry as read"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE user_inquiries SET is_read = 1 WHERE id = %s",
            (inquiry_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error marking inquiry as read: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def mark_all_inquiries_as_read():
    """Mark all user inquiries as read"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE user_inquiries SET is_read = 1")
        conn.commit()
        return True
    except Exception as e:
        print(f"Error marking all inquiries as read: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def notify_inquiry_resolved(user_id, subject):
    """Create notification when admin resolves a user inquiry"""
    title = "Inquiry Resolved"
    message = f"Your inquiry '{subject}' has been resolved by an administrator"
    return create_notification(user_id, 'inquiry_resolved', title, message)