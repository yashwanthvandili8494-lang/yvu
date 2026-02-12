-- SQLite version of the quizapp database schema

PRAGMA foreign_keys = ON;

-- Table structure for table `longqa`
CREATE TABLE `longqa` (
  `longqa_qid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `q` TEXT NOT NULL,
  `marks` INTEGER,
  `uid` INTEGER,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `longtest`
CREATE TABLE `longtest` (
  `longtest_qid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `qid` INTEGER NOT NULL,
  `ans` TEXT NOT NULL,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `practicalqa`
CREATE TABLE `practicalqa` (
  `pracqa_qid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `q` TEXT NOT NULL,
  `compiler` INTEGER NOT NULL,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `practicaltest`
CREATE TABLE `practicaltest` (
  `pid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `code` TEXT,
  `input` TEXT,
  `executed` TEXT,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `proctoring_log`
CREATE TABLE `proctoring_log` (
  `pid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `name` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `voice_db` INTEGER DEFAULT 0,
  `img_log` TEXT NOT NULL,
  `user_movements_updown` INTEGER NOT NULL,
  `user_movements_lr` INTEGER NOT NULL,
  `user_movements_eyes` INTEGER NOT NULL,
  `phone_detection` INTEGER NOT NULL,
  `person_status` INTEGER NOT NULL,
  `log_time` TEXT DEFAULT CURRENT_TIMESTAMP,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `questions`
CREATE TABLE `questions` (
  `questions_uid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `test_id` TEXT NOT NULL,
  `qid` TEXT NOT NULL,
  `q` TEXT NOT NULL,
  `a` TEXT NOT NULL,
  `b` TEXT NOT NULL,
  `c` TEXT NOT NULL,
  `d` TEXT NOT NULL,
  `ans` TEXT NOT NULL,
  `marks` INTEGER NOT NULL,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `students`
CREATE TABLE `students` (
  `sid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `qid` TEXT,
  `ans` TEXT,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `studenttestinfo`
CREATE TABLE `studenttestinfo` (
  `stiid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `time_left` INTEGER NOT NULL,
  `completed` INTEGER DEFAULT 0,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `teachers`
CREATE TABLE `teachers` (
  `tid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `test_type` TEXT NOT NULL,
  `start` TEXT NOT NULL,
  `end` TEXT NOT NULL,
  `duration` INTEGER NOT NULL,
  `show_ans` INTEGER NOT NULL,
  `password` TEXT NOT NULL,
  `subject` TEXT NOT NULL,
  `topic` TEXT NOT NULL,
  `neg_marks` INTEGER NOT NULL,
  `calc` INTEGER NOT NULL,
  `proctoring_type` INTEGER DEFAULT 0,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);

-- Table structure for table `users`
CREATE TABLE `users` (
  `uid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `name` TEXT NOT NULL,
  `email` TEXT NOT NULL UNIQUE,
  `password` TEXT NOT NULL,
  `register_time` TEXT DEFAULT CURRENT_TIMESTAMP,
  `user_type` TEXT NOT NULL,
  `user_image` TEXT NOT NULL,
  `user_login` INTEGER NOT NULL,
  `examcredits` INTEGER DEFAULT 7
);

-- Table structure for table `window_estimation_log`
CREATE TABLE `window_estimation_log` (
  `wid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `email` TEXT NOT NULL,
  `test_id` TEXT NOT NULL,
  `name` TEXT NOT NULL,
  `window_event` INTEGER NOT NULL,
  `transaction_log` TEXT DEFAULT CURRENT_TIMESTAMP,
  `uid` INTEGER NOT NULL,
  FOREIGN KEY (`uid`) REFERENCES `users` (`uid`)
);
