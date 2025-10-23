# Threat-Scope: PHP Vulnerability Scanner

A comprehensive web-based PHP vulnerability scanner that uses machine learning and static analysis to detect SQL injection vulnerabilities in PHP source code.

## Features

### 🔍 Vulnerability Detection
- **Machine Learning**: Uses Logistic Regression with TF-IDF vectorization to classify potentially unsafe code lines
- **Static Analysis**: Implements taint analysis to track data flow from user inputs to SQL queries
- **Real-time Scanning**: Upload PHP files and get instant vulnerability analysis

### 🗄️ Database Management
- **MySQL Integration**: Full MySQL support with phpMyAdmin interface
- **SQLite Fallback**: Automatic fallback to SQLite for development
- **Advanced Analytics**: Comprehensive statistics and trend analysis
- **Data Export**: CSV export functionality for scan results

### 🌐 Web Interface
- **Modern UI**: Clean, responsive interface built with Tailwind CSS
- **Real-time Results**: Interactive vulnerability display with detailed reports
- **Scan History**: Complete history of all scans with statistics
- **Database Dashboard**: phpMyAdmin-like interface for data management

## Quick Start

### Using Docker (Recommended)

1. **Clone and navigate to the project:**
   ```bash
   git clone <repository-url>
   cd threat-scope
   ```

2. **Start the services:**
   ```bash
   docker-compose up -d
   ```

3. **Access the applications:**
   - **Main Scanner**: http://127.0.0.1:5000 (or http://localhost:5000)
   - **phpMyAdmin**: http://localhost:8080
   - **MySQL**: localhost:3306

### Manual Setup

1. **Install dependencies:**
   ```bash
   cd web
   pip install -r requirements.txt
   ```

2. **Set up MySQL (optional):**
   ```bash
   # Create database
   mysql -u root -p
   CREATE DATABASE threat_scope;
   CREATE USER 'threat_user'@'localhost' IDENTIFIED BY 'threat_password';
   GRANT ALL PRIVILEGES ON threat_scope.* TO 'threat_user'@'localhost';
   ```

3. **Set environment variables:**
   ```bash
   export DATABASE_URL="mysql+pymysql://threat_user:threat_password@localhost:3306/threat_scope"
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```

## Database Migration

If you have existing SQLite data, migrate it to MySQL:

```bash
cd web
python migrate_to_mysql.py
```

## Usage

### 1. Upload and Scan
- Navigate to http://127.0.0.1:5000 (or http://localhost:5000)
- Upload a PHP file using the drag-and-drop interface
- View real-time vulnerability analysis results

### 2. View Scan History
- Click on "Past Scans" tab to see all previous scans
- View detailed statistics for each scan
- Click on any scan to view its results

### 3. Database Management
- Click on "Database" tab to access the management interface
- View comprehensive statistics and analytics
- Export data as CSV
- Delete individual scans

### 4. phpMyAdmin Access
- Navigate to http://localhost:8080
- Login with MySQL credentials
- Direct database access and management

## API Endpoints

### Scan Management
- `GET /api/scans` - Get paginated scan data
- `GET /api/stats` - Get system statistics
- `DELETE /api/scan/<id>/delete` - Delete a specific scan

### Data Export
- `GET /api/export/csv` - Export all scan data as CSV

## Project Structure

```
threat-scope/
├── web/                    # Flask web application
│   ├── app.py             # Main Flask application
│   ├── templates/         # HTML templates
│   │   ├── index.html     # Main scanner interface
│   │   └── database.html  # Database management interface
│   ├── static/            # CSS and static files
│   ├── scripts/           # Detection scripts
│   └── requirements.txt   # Python dependencies
├── data/                  # Training data
│   ├── train/safe/        # Safe PHP files
│   └── train/unsafe/      # Unsafe PHP files
├── models/                # Trained ML models
├── scripts/               # Training and analysis scripts
├── docker-compose.yml     # Docker configuration
└── README.md             # This file
```

## Machine Learning Model

The scanner uses a Logistic Regression classifier trained on:
- **Features**: TF-IDF vectorization with character n-grams (3-5 characters)
- **Training Data**: 8,640 safe and 912 unsafe PHP files
- **Analysis**: Line-level vulnerability detection with taint analysis

## Database Schema

### Scan Table
- `id`: Primary key
- `filename`: Name of scanned file
- `timestamp`: When the scan was performed
- `results`: JSON containing detailed scan results
- `total_lines`: Total number of lines in the file
- `unsafe_lines`: Number of unsafe lines detected
- `safe_lines`: Number of safe lines
- `file_size`: File size in bytes

## Development

### Training the Model
```bash
cd scripts
python prepare_data.py
python train_model.py --input preprocessed/train_linelevel.csv --model_out ../models/logreg_model.pkl --vectorizer_out ../models/tfidf_vectorizer.pkl
```

### Testing Detection
```bash
python scripts/detect_lines.py --file path/to/file.php --model models/logreg_model.pkl --vectorizer models/tfidf_vectorizer.pkl --threshold 0.7
```

## Configuration

### Environment Variables
- `DATABASE_URL`: Database connection string
- `FLASK_ENV`: Flask environment (development/production)

### Docker Environment
- MySQL root password: `rootpassword`
- Database: `threat_scope`
- User: `threat_user`
- Password: `threat_password`

## Security Features

- **Input Validation**: Secure file upload handling
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Proper output escaping
- **CSRF Protection**: Flask-WTF integration

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check MySQL service is running
   - Verify connection credentials
   - Ensure database exists

2. **Model Loading Error**
   - Ensure model files exist in `models/` directory
   - Check file permissions

3. **Docker Issues**
   - Run `docker-compose down` and `docker-compose up -d`
   - Check logs with `docker-compose logs`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Training data based on CWE-89 (SQL Injection) vulnerability patterns
- Machine learning implementation using scikit-learn
- Web interface built with Flask and Tailwind CSS