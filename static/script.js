$(document).ready(function(){
    $("#form0").submit(function(event){
    if($("#pass").val().length<8){
        event.preventDefault();
		$("#statue").css("width","75%")
		$("#statue").html("Please Enter Vaild Password");
    }else{
		$("#statue").html("Logging...");
    }
    
    });
});
