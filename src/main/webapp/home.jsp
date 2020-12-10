<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<c:set var="contextPath" value="${pageContext.request.contextPath}"/>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Home</title>
    <link href="${contextPath}/resources/css/bootstrap.min.css" rel="stylesheet">
    <link href="${contextPath}/resources/css/common.css" rel="stylesheet">
</head>

<body>
<div class="container">
    <c:if test="${pageContext.request.userPrincipal.name != null}">
        <h2>Hello ${pageContext.request.userPrincipal.name}!</h2>

        <form id="logoutForm" method="POST" action="${contextPath}/logout">
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
        </form>

        <form:form method="POST" modelAttribute="userForm" class="form-data">

            <spring:bind path="sensitiveData">
                <div class="form-group ${status.error ? 'has-error' : ''}">
                    <form:input
                            type="text"
                            path="sensitiveData"
                            class="form-control"
                            placeholder="Sensitive data"
                    />
                    <form:errors path="sensitiveData"/>
                </div>
            </spring:bind>

            <button class="btn btn-lg btn-primary btn-block" type="submit">Update</button>

        </form:form>

        <button class="btn btn-lg btn-primary btn-block" onclick="document.forms['logoutForm'].submit()">
            Logout
        </button>
    </c:if>
</div>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script src="${contextPath}/resources/js/bootstrap.min.js"></script>

</body>
</html>