import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QFormLayout,
    QMessageBox, QLabel
)
import requests
import webbrowser
from urllib.parse import urlencode
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

# SQLAlchemy setup
DATABASE_URL = "sqlite:///user_data.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# User model
class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String, nullable=True)
    api_secret = Column(String, nullable=True)
    redirect_url = Column(String, nullable=True)
    access_token = Column(String, nullable=True)  # New column
    code = Column(String, nullable=True)         # New column

# Create the user table if it doesn't exist
Base.metadata.create_all(engine)

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login Window")

        # Create a form layout for the fields
        form_layout = QFormLayout()

        # Add fields
        self.client_id = QLineEdit()
        self.api_secret = QLineEdit()
        self.redirect_url = QLineEdit()
        self.code = QLineEdit()
        self.access_token = QLineEdit()

        # Prefill fields from database
        self.prefill_fields()

        # Add widgets to the form layout
        form_layout.addRow("Client ID:", self.client_id)
        form_layout.addRow("API Secret:", self.api_secret)
        form_layout.addRow("Redirect URL:", self.redirect_url)

        # Add the Authorise button below the Redirect URL
        self.authorise_button = QPushButton("Authorise")
        self.authorise_button.clicked.connect(self.handle_authorise)  # Connect button click to handler
        form_layout.addRow(self.authorise_button)  # Add the button as a standalone row

        form_layout.addRow("Code:", self.code)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        form_layout.addRow(self.login_button)

        form_layout.addRow("Access Token:", self.access_token)
        
        self.test_button = QPushButton("Test")
        self.test_button.clicked.connect(self.test_user_info)
        form_layout.addRow(self.test_button)

        # Set layout for the LoginWindow
        self.setLayout(form_layout)
        
    def test_user_info(self):
        url = 'https://api.upstox.com/v2/user/profile'
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {self.access_token.text()}',
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
            user_info = response.json()

            # Save access_token and code to database
            user = session.query(User).first()
            if user:
                user.access_token = self.access_token.text()
                user.code = self.code.text()
                session.commit()

            # Display user information
            QMessageBox.information(self, "User Info", f"User Info: {user_info}")
        except requests.exceptions.HTTPError as http_err:
            QMessageBox.critical(self, "HTTP Error", f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            QMessageBox.critical(self, "Request Error", f"An error occurred: {req_err}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
        
    def prefill_fields(self):
        user = session.query(User).first()
        if user:
            self.client_id.setText(user.client_id or "")
            self.api_secret.setText(user.api_secret or "")
            self.redirect_url.setText(user.redirect_url or "")
            self.access_token.setText(user.access_token or "")
            self.code.setText(user.code or "")

    def handle_authorise(self):
        url = "https://api.upstox.com/v2/login/authorization/dialog/"
        params = {
            "client_id": self.client_id.text(),
            "response_type": "code",
            "redirect_uri": self.redirect_url.text(),
        }
        # Encode parameters and append to the URL
        full_url = f"{url}?{urlencode(params)}"

        # Open the URL in the default web browser
        webbrowser.open(full_url, new=0, autoraise=True)

    def handle_login(self):
        url = 'https://api.upstox.com/v2/login/authorization/token'
        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'code': self.code.text(),
            'client_id': self.client_id.text(),
            'client_secret': self.api_secret.text(),
            'redirect_uri': self.redirect_url.text(),
            'grant_type': 'authorization_code',
        }
        response = requests.post(url, headers=headers, data=data)
        response_data = response.json()
        print(response_data)
        access_token = 'access_token'
        if access_token in response_data:
            self.access_token.setText(response_data[access_token])
            self.save_to_database()
        else:
            print('Reauthorise')

    def save_to_database(self):
        # Clear existing user data
        session.query(User).delete()

        # Save new user data
        new_user = User(
            client_id=self.client_id.text(),
            api_secret=self.api_secret.text(),
            redirect_url=self.redirect_url.text(),
            access_token=self.access_token.text(),
            code=self.code.text()
        )
        session.add(new_user)
        session.commit()
        print("User data saved to database.")
        
class TradeWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Trade Window")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("No Code Algo Trading")

        # Create a "Login" button
        self.login_button = QPushButton("Login", self)
        self.login_button.clicked.connect(self.open_login_window)
        
        self.trade_button = QPushButton("Trade", self)
        self.trade_button.clicked.connect(self.open_trade_window)

        # Create a layout to stack the label and button
        layout = QVBoxLayout()
        layout.addWidget(self.login_button)

        # Create a central widget
        central_widget = QWidget()
        central_widget.setLayout(layout)
        
        self.setCentralWidget(central_widget)
        self.status_label = QLabel(self)
        layout.addWidget(self.status_label)
        
        status = self.check_status()
        if status:
            layout.addWidget(self.trade_button)
            self.status_label.setText("🟢 Connected")
        else:
            self.status_label.setText("🔴 Disconnected")

    def open_login_window(self):
        # Open the login window
        self.login_window = LoginWindow()
        self.login_window.resize(400, 300)
        self.login_window.show()
    
    def open_trade_window(self):
        # Open the login window
        self.trade_window = TradeWindow()
        self.trade_window.resize(400, 300)
        self.trade_window.show()
    
    def check_status(self):
        user = session.query(User).first()
        if user and user.access_token:
            url = 'https://api.upstox.com/v2/user/profile'
            headers = {
                'accept': 'application/json',
                'Authorization': f'Bearer {user.access_token}',
            }
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
                user_info = response.json()
                print(user_info)
                return True
            except:
                print('Reauthorise')
                return False
        else:
            print('Reauthorise')
            return False

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(400, 300)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
