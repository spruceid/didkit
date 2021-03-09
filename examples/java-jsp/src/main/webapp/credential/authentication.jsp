<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<html>
<head>
    <title>Java JSP Example - Get Authentication Credential</title>
</head>
<body>
<p><a href="${pageContext.request.contextPath}/">Back</a></p>
<form method="post" action="${pageContext.request.contextPath}/credential/authentication">
    <p><label>DID:<input id="did" name="did" placeholder="did:example:abcd1234"/></label></p>
    <p><input type="submit" value="Get Credential"/></p>
</form>
</body>
</html>
