import psycopg2
import os
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from datetime import datetime

bcrypt = Bcrypt()

# Establish database connection
connection = psycopg2.connect(
    host=os.getenv('DB_HOST', 'localhost'),
    database=os.getenv('DB_NAME', 'hospital_db'),
    user=os.getenv('DB_USER', 'postgres'),
    password=os.getenv('DB_PASSWORD')
)
cursor = connection.cursor()

class User(UserMixin):
    def __init__(self, id, username, email, password, role):
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.role = role

    @staticmethod
    def create(username, email, password, role):
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("""
            INSERT INTO users (username, email, password, role)
            VALUES (%s, %s, %s, %s) RETURNING id
        """, (username, email, hashed_password, role))
        connection.commit()
        return cursor.fetchone()[0]

    @staticmethod
    def find_by_username_and_role(username, role):
        cursor.execute("SELECT * FROM users WHERE username = %s AND role = %s", (username, role))
        user_data = cursor.fetchone()
        if user_data:
            return User(id=user_data[0], username=user_data[1], email=user_data[2], password=user_data[3], role=user_data[4])
        return None

    @staticmethod
    def get_all_users():
        cursor.execute("SELECT * FROM users")
        return cursor.fetchall()

class Hospital:
    @staticmethod
    def create(name, location, services, rating):
        cursor.execute("""
            INSERT INTO hospitals (name, location, services, rating)
            VALUES (%s, %s, %s, %s)
        """, (name, location, services, rating))
        connection.commit()

    @staticmethod
    def get_all_hospitals():
        cursor.execute("SELECT * FROM hospitals")
        return cursor.fetchall()

class Appointment:
    @staticmethod
    def create(patient_id, doctor_id, hospital_id, date, status):
        cursor.execute("""
            INSERT INTO appointments (patient_id, doctor_id, hospital_id, date, status)
            VALUES (%s, %s, %s, %s, %s)
        """, (patient_id, doctor_id, hospital_id, date, status))
        connection.commit()

    @staticmethod
    def get_appointments_by_doctor(doctor_id):
        cursor.execute("SELECT * FROM appointments WHERE doctor_id = %s", (doctor_id,))
        return cursor.fetchall()

    @staticmethod
    def get_appointments_by_patient(patient_id):
        cursor.execute("SELECT * FROM appointments WHERE patient_id = %s", (patient_id,))
        return cursor.fetchall()

class Prescription:
    @staticmethod
    def create(doctor_id, patient_id, appointment_id, medicines, instructions):
        cursor.execute("""
            INSERT INTO prescriptions (doctor_id, patient_id, appointment_id, medicines, instructions)
            VALUES (%s, %s, %s, %s, %s)
        """, (doctor_id, patient_id, appointment_id, medicines, instructions))
        connection.commit()

    @staticmethod
    def get_prescriptions_by_patient(patient_id):
        cursor.execute("SELECT * FROM prescriptions WHERE patient_id = %s", (patient_id,))
        return cursor.fetchall()

class AmbulanceBooking:
    @staticmethod
    def create(patient_id, hospital_id, pickup_location, status):
        cursor.execute("""
            INSERT INTO ambulance_bookings (patient_id, hospital_id, pickup_location, status)
            VALUES (%s, %s, %s, %s)
        """, (patient_id, hospital_id, pickup_location, status))
        connection.commit()

    @staticmethod
    def get_all_bookings():
        cursor.execute("SELECT * FROM ambulance_bookings")
        return cursor.fetchall()

class MedicalOrder:
    @staticmethod
    def create(patient_id, prescription_id, order_status):
        cursor.execute("""
            INSERT INTO medical_orders (patient_id, prescription_id, order_status)
            VALUES (%s, %s, %s)
        """, (patient_id, prescription_id, order_status))
        connection.commit()

    @staticmethod
    def get_orders_by_patient(patient_id):
        cursor.execute("SELECT * FROM medical_orders WHERE patient_id = %s", (patient_id,))
        return cursor.fetchall()

class OTPVerification:
    @staticmethod
    def create(user_id, otp_code, expires_at):
        cursor.execute("""
            INSERT INTO otp_verifications (user_id, otp_code, expires_at)
            VALUES (%s, %s, %s)
        """, (user_id, otp_code, expires_at))
        connection.commit()

    @staticmethod
    def verify_otp(user_id, otp_code):
        cursor.execute("""
            SELECT * FROM otp_verifications WHERE user_id = %s AND otp_code = %s AND expires_at > NOW() AND verified = FALSE
        """, (user_id, otp_code))
        otp_record = cursor.fetchone()
        if otp_record:
            cursor.execute("""
                UPDATE otp_verifications SET verified = TRUE WHERE id = %s
            """, (otp_record[0],))
            connection.commit()
            return True
        return False

class Patient:
    @staticmethod
    def create(name, email):
        cursor.execute("""
            INSERT INTO patients (name, email)
            VALUES (%s, %s)
        """, (name, email))
        connection.commit()

    @staticmethod
    def get_all_patients():
        cursor.execute("SELECT * FROM patients")
        return cursor.fetchall()

class Notification:
    @staticmethod
    def create(message, is_active=True):
        cursor.execute("""
            INSERT INTO notifications (message, is_active)
            VALUES (%s, %s)
        """, (message, is_active))
        connection.commit()

    @staticmethod
    def get_all_notifications():
        cursor.execute("SELECT * FROM notifications")
        return cursor.fetchall()

    @staticmethod
    def deactivate_notification(notification_id):
        cursor.execute("""
            UPDATE notifications SET is_active = FALSE WHERE id = %s
        """, (notification_id,))
        connection.commit()

class ConsultationNote:
    @staticmethod
    def create(doctor_id, patient_id, note_content):
        cursor.execute("""
            INSERT INTO consultation_notes (doctor_id, patient_id, note_content, timestamp)
            VALUES (%s, %s, %s, %s)
        """, (doctor_id, patient_id, note_content, datetime.utcnow()))
        connection.commit()

    @staticmethod
    def get_notes_by_doctor(doctor_id):
        cursor.execute("SELECT * FROM consultation_notes WHERE doctor_id = %s", (doctor_id,))
        return cursor.fetchall()

    @staticmethod
    def get_notes_by_patient(patient_id):
        cursor.execute("SELECT * FROM consultation_notes WHERE patient_id = %s", (patient_id,))
        return cursor.fetchall()

    @staticmethod
    def get_note_by_id(note_id):
        cursor.execute("SELECT * FROM consultation_notes WHERE note_id = %s", (note_id,))
        return cursor.fetchone()

    @staticmethod
    def update_note(note_id, note_content):
        cursor.execute("""
            UPDATE consultation_notes
            SET note_content = %s, timestamp = %s
            WHERE note_id = %s
        """, (note_content, datetime.utcnow(), note_id))
        connection.commit()

    @staticmethod
    def delete_note(note_id):
        cursor.execute("DELETE FROM consultation_notes WHERE note_id = %s", (note_id,))
        connection.commit()

class Hospital:
    def __init__(self, id, name, location, rating):
        self.id = id
        self.name = name
        self.location = location
        self.rating = rating

    @staticmethod
    def create(name, location, rating):
        cursor.execute("""
            INSERT INTO hospitals (name, location, rating)
            VALUES (%s, %s, %s) RETURNING id
        """, (name, location, rating))
        connection.commit()
        return cursor.fetchone()[0]

    @staticmethod
    def get_all_hospitals():
        cursor.execute("SELECT * FROM hospitals")
        hospitals_data = cursor.fetchall()
        return [Hospital(id=h[0], name=h[1], location=h[2], rating=h[3]) for h in hospitals_data]

    @staticmethod
    def find_by_id(hospital_id):
        cursor.execute("SELECT * FROM hospitals WHERE id = %s", (hospital_id,))
        hospital_data = cursor.fetchone()
        if hospital_data:
            return Hospital(id=hospital_data[0], name=hospital_data[1], location=hospital_data[2], rating=hospital_data[3])
        return None

class HospitalService:
    def __init__(self, id, hospital_id, service_name):
        self.id = id
        self.hospital_id = hospital_id
        self.service_name = service_name

    @staticmethod
    def create(hospital_id, service_name):
        cursor.execute("""
            INSERT INTO hospital_services (hospital_id, service_name)
            VALUES (%s, %s) RETURNING id
        """, (hospital_id, service_name))
        connection.commit()
        return cursor.fetchone()[0]

    @staticmethod
    def get_services_by_hospital(hospital_id):
        cursor.execute("SELECT * FROM hospital_services WHERE hospital_id = %s", (hospital_id,))
        services_data = cursor.fetchall()
        return [HospitalService(id=s[0], hospital_id=s[1], service_name=s[2]) for s in services_data]

    @staticmethod
    def get_all_services():
        cursor.execute("SELECT * FROM hospital_services")
        services_data = cursor.fetchall()
        return [HospitalService(id=s[0], hospital_id=s[1], service_name=s[2]) for s in services_data]
