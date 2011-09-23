-- phpMyAdmin SQL Dump
-- version 2.10.0.2
-- http://www.phpmyadmin.net
-- 
-- Host: localhost
-- Generation Time: Mar 30, 2007 at 09:31 PM
-- Server version: 5.0.37
-- PHP Version: 5.2.1

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";

-- 
-- Database: `chat`
-- 

-- --------------------------------------------------------

-- 
-- Table structure for table `rooms`
-- 

CREATE TABLE `rooms` (
  `jid` varchar(512) NOT NULL,
  `name` text NOT NULL,
  `desc` text NOT NULL,
  `topic` text NOT NULL,
  `users` int(11) NOT NULL default '0',
  `public` tinyint(1) NOT NULL,
  `open` tinyint(1) NOT NULL,
  `secret` text NOT NULL,
  UNIQUE KEY `jid` (`jid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

-- 
-- Table structure for table `rooms_lists`
-- 

CREATE TABLE `rooms_lists` (
  `jid_room` varchar(512) NOT NULL,
  `jid_user` varchar(512) NOT NULL,
  `affil` enum('administrator','owner','member','outcast') NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
