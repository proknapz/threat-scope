# Use official Python image
FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Copy requirements if you have one (or install directly)
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy app and templates
COPY app.py .
COPY templates/ ./templates
COPY ../models ./models

# Create uploads folder
RUN mkdir -p uploads

# Expose port
EXPOSE 5000

# Run Flask
CMD ["python", "app.py"]
