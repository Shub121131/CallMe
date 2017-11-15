package com.ordernao.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

	@RequestMapping(value = {"/login","/logout"})
	public String showloginGet(HttpServletRequest request, HttpServletResponse response) {
		return "login";
	}

	@PostMapping(value = {"/login","/logout"})
	public String showloginPost(HttpServletRequest request, HttpServletResponse response) {
		return "login";
	}
	@RequestMapping(value = {"/"})
	public String showIndexPage(HttpServletRequest request, HttpServletResponse response) {
		return "index";
	}
	
	@RequestMapping(value = {"/homepage.html"})
	public String showHome(HttpServletRequest request, HttpServletResponse response) {
		return "homepage";
	}
	
	@PostMapping(value = {"/homepage.html"})
	public String showHomePost(HttpServletRequest request, HttpServletResponse response) {
		return "homepage";
	}

	@RequestMapping(value = "/addemploy.html")
	public String addEmployee(HttpServletRequest request, HttpServletResponse response) {
		return "addemploy";
	}
    
    
   /* @RequestMapping(value = "/login")
	public String showloginGet(HttpServletRequest request, HttpServletResponse response) {
		return "login";
	}

	@PostMapping(value = "/login")
	public String showloginPost(HttpServletRequest request, HttpServletResponse response) {
		return "login";
	}
	@RequestMapping(value = {"/homepage.html","/"})
	public String showHome(HttpServletRequest request, HttpServletResponse response) {
		return "homepage";
	}

	@RequestMapping(value = "/addemploy.html")
	public String addEmployee(HttpServletRequest request, HttpServletResponse response) {
		return "addemploy";
	}*/

}
