# LinkedIn Connection Aggregator Tool

## Overview

The LinkedIn Connection Aggregator Tool is a Flask-based web application designed to help organizations collect, aggregate, and search through employee LinkedIn connections. The system allows employees to upload their LinkedIn connection data via CSV files and provides powerful search functionality to find connections across the entire organization. This enables companies to leverage their collective professional network for business development, recruitment, and partnership opportunities.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes (August 16, 2025)

- **Bulk Upload Workflow**: Modified system to support uploading multiple employee CSV files without creating separate user accounts
- **Automatic Name Detection**: Added smart filename parsing to automatically extract employee names from CSV filenames
- **Download Feature**: Added CSV download capability for search results with proper formatting and personalized filenames
- **Database Schema Fix**: Updated employees table to allow NULL passwords for CSV-imported employees
- **Password Management**: Added secure password change functionality accessible from the dashboard sidebar
- **Forgot Password Feature**: Added email-based password reset with temporary password generation
- **Streamlined Interface**: Removed dashboard statistics and made recent searches clickable for quick re-execution
- **Admin Access**: Updated registration to automatically create all new accounts as admin accounts
- **Contact Name Search**: Added ability to search by contact first name, last name, or both with intelligent fuzzy matching

## System Architecture

### Frontend Architecture
The application uses a server-side rendered architecture with Flask templates, utilizing Bootstrap for responsive UI components and JavaScript for client-side interactions. The frontend consists of:
- **Template Engine**: Jinja2 templates with a dark theme Bootstrap CSS framework
- **Static Assets**: Custom CSS for LinkedIn branding and JavaScript for form handling and user interactions
- **Client-side Features**: File upload validation, form submission loading states, and tooltip initialization

### Backend Architecture
The system is built on Flask with a modular approach:
- **Web Framework**: Flask with CORS support for cross-origin requests
- **Authentication**: Session-based authentication using werkzeug security utilities
- **File Handling**: Secure file upload system with size and type validation
- **Search Engine**: FuzzyWuzzy library for intelligent connection matching and searching
- **Data Processing**: Pandas for CSV file processing and data manipulation

### Database Design
The application uses SQLite as the primary database with the following key tables:
- **Employees Table**: Stores user accounts with email, name, department, and hashed passwords
- **Connections Table**: Stores LinkedIn connection data with employee associations
- **File Uploads Tracking**: Maintains records of uploaded CSV files and processing status

### Authentication System
- **Password Security**: Uses werkzeug's password hashing for secure credential storage
- **Session Management**: Flask sessions for maintaining user authentication state
- **Access Control**: Route-level protection ensuring users can only access their own data

### File Processing Pipeline
- **Multi-File Upload**: Supports bulk upload of multiple employee CSV files in a single operation
- **Automatic Employee Detection**: Intelligently extracts employee names from filenames and creates employee records
- **Upload Validation**: Checks file type (CSV only) and size limits (16MB maximum)
- **CSV Processing**: Handles LinkedIn export format by automatically detecting and skipping header notes, supports multiple encodings and parsing methods
- **Data Normalization**: Cleans and standardizes connection data before database insertion with flexible column name mapping
- **Duplicate Handling**: Prevents duplicate connections through database constraints
- **Batch Processing Results**: Provides comprehensive summary of all processed files with success/failure reporting

## External Dependencies

### Core Framework Dependencies
- **Flask**: Web application framework with template rendering and routing
- **Flask-CORS**: Cross-origin resource sharing support
- **Werkzeug**: Security utilities for password hashing and file handling

### Data Processing Libraries
- **Pandas**: CSV file processing and data manipulation
- **FuzzyWuzzy**: Fuzzy string matching for intelligent search functionality
- **SQLite3**: Embedded database for data persistence

### Frontend Libraries (CDN)
- **Bootstrap 5**: UI framework with dark theme support
- **Font Awesome**: Icon library for enhanced user interface
- **Bootstrap JavaScript**: Client-side component functionality

### Development and Deployment
- **Python Standard Library**: datetime, os, json, re, hashlib, logging for core functionality
- **File System**: Local uploads directory for temporary CSV file storage
- **Environment Variables**: Configuration management for secrets and settings