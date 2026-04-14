import os
import mysql.connector
from datetime import datetime

def get_db_connection(app_config):
    """
    Create a database connection using the application configuration
    
    Args:
        app_config: Flask application configuration containing database settings
        
    Returns:
        MySQL database connection
    """
    return mysql.connector.connect(
        host=app_config['MYSQL_HOST'],
        user=app_config['MYSQL_USER'],
        password=app_config['MYSQL_PASSWORD'],
        database=app_config['MYSQL_DB']
    )

def get_user_upload_stats(app_config):
    """
    Get upload statistics for all users
    
    Args:
        app_config: Flask application configuration containing database settings
        
    Returns:
        List of dictionaries containing user upload statistics
    """
    conn = get_db_connection(app_config)
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get all users with their details
        cursor.execute("""
            SELECT 
                u.id, 
                u.username,
                CONCAT(
                    COALESCE(b.first_name, g.first_name, e.first_name, ''), ' ',
                    COALESCE(b.last_name, g.last_name, e.last_name, '')
                ) AS full_name,
                COALESCE(b.email, g.email, e.email) AS email
            FROM users u
            LEFT JOIN brgycaptain b ON u.id = b.user_id
            LEFT JOIN government_position g ON u.id = g.user_id
            LEFT JOIN employee e ON u.id = e.user_id
        """)
        
        users = cursor.fetchall()
        
        # Get upload statistics for each user
        for user in users:
            # Get total uploaded files count
            cursor.execute("SELECT COUNT(*) as file_count FROM files WHERE owner_id = %s", (user['id'],))
            file_count = cursor.fetchone()['file_count']
            user['uploaded_files_count'] = file_count
            
            # Get total uploaded size
            cursor.execute("SELECT filename FROM files WHERE owner_id = %s", (user['id'],))
            files = cursor.fetchall()
            
            total_size = 0
            for file in files:
                file_path = os.path.join('uploads', file['filename'])
                if os.path.exists(file_path):
                    total_size += os.path.getsize(file_path)
            
            user['total_uploaded_gb'] = round(total_size / (1024 * 1024 * 1024), 2)  # Convert bytes to GB
            
            # Get total downloads (files shared with others)
            cursor.execute("""
                SELECT COUNT(*) as download_count 
                FROM files 
                WHERE owner_id = %s AND shared_with IS NOT NULL
            """, (user['id'],))
            download_count = cursor.fetchone()['download_count']
            user['shared_files_count'] = download_count
            
        return users
    
    except Exception as e:
        print(f"Error getting user upload stats: {e}")
        return []
    
    finally:
        cursor.close()
        conn.close()

def get_user_file_stats(app_config, user_id):
    """
    Get detailed file statistics for a specific user
    
    Args:
        app_config: Flask application configuration containing database settings
        user_id: User ID to get statistics for
        
    Returns:
        Dictionary containing detailed file statistics
    """
    conn = get_db_connection(app_config)
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get user details
        cursor.execute("""
            SELECT 
                u.id, 
                u.username,
                CONCAT(
                    COALESCE(b.first_name, g.first_name, e.first_name, ''), ' ',
                    COALESCE(b.last_name, g.last_name, e.last_name, '')
                ) AS full_name,
                COALESCE(b.email, g.email, e.email) AS email
            FROM users u
            LEFT JOIN brgycaptain b ON u.id = b.user_id
            LEFT JOIN government_position g ON u.id = g.user_id
            LEFT JOIN employee e ON u.id = e.user_id
            WHERE u.id = %s
        """, (user_id,))
        
        user = cursor.fetchone()
        if not user:
            return None
        
        # Get uploaded files with details
        cursor.execute("""
            SELECT id, filename, created_at, size, shared_with
            FROM files 
            WHERE owner_id = %s
        """, (user_id,))
        
        files = cursor.fetchall()
        
        # Calculate statistics
        total_size = 0
        file_count = len(files)
        shared_count = 0
        file_details = []
        
        for file in files:
            # Convert size to MB for display
            if file['size']:
                size_mb = round(file['size'] / (1024 * 1024), 2)
            else:
                size_mb = 0
                
            file_details.append({
                'id': file['id'],
                'filename': file['filename'],
                'created_at': file['created_at'],
                'size_mb': size_mb,
                'shared': file['shared_with'] is not None
            })
            
            total_size += file['size'] if file['size'] else 0
            if file['shared_with'] is not None:
                shared_count += 1
        
        # Convert total size to GB
        total_size_gb = round(total_size / (1024 * 1024 * 1024), 2)
        
        return {
            'user': user,
            'stats': {
                'total_files': file_count,
                'total_size_gb': total_size_gb,
                'shared_files': shared_count
            },
            'files': file_details
        }
    
    except Exception as e:
        print(f"Error getting user file stats: {e}")
        return None
    
    finally:
        cursor.close()
        conn.close()