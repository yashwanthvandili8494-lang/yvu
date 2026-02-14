# Project Fix TODO List

## Phase 1: Fix Critical Database Issues
- [x] Fix MySQLConnection class - add connection property
- [ ] Fix CompatMySQLCursor parameter normalization
- [x] Update all database query calls throughout app.py (via property fix)

## Phase 2: Fix Dependencies
- [ ] Add missing packages to requirements.txt (opencv-python, tensorflow, gaze-tracking)
- [ ] Add NLTK data download setup

## Phase 3: Fix Camera Module
- [ ] Add error handling for model loading in camera.py
- [ ] Make proctoring features optional/failsafe
- [ ] Add proper logging

## Phase 4: Fix Code Quality
- [ ] Remove duplicate function countMTOPstudentslogs
- [ ] Add input validation
- [ ] Fix global variable usage (duration, marked_ans, etc.)
- [ ] Add proper error handling throughout

## Phase 5: Improve Functionality
- [ ] Add proper session management
- [ ] Improve question generation (objective.py, subjective.py)
- [ ] Add better logging and diagnostics
