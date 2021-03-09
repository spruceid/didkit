<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<html>
<head>
    <title>Java JSP Example - Sign Up</title>
</head>
<body>
<p><a href="${pageContext.request.contextPath}/">Back</a></p>
<form method="post" action="${pageContext.request.contextPath}/sign-up">
    <p><label>Username:<input id="username" name="username" placeholder="username"/></label></p>
    <p><label>Password:<input id="password" name="password" placeholder="password" type="password"/></label></p>
    <p><input type="submit" value="Sign Up"/></p>
</form>
</body>
</html>
