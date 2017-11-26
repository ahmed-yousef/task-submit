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
function submit_it(){
		//console.log("hello there");
		var formElement = document.querySelector("form");
		var data = new FormData(formElement);
		//console.log(data);
		for(var i = 0;i<$( '#file' )[0].files.length;i++){
        data.append( 'file', $( '#file' )[0].files[i] );
		}
		//console.log(data);
		var url="/submit";
		var ajax = new XMLHttpRequest();
        ajax.upload.addEventListener("progress", progressHandler, false);
		ajax.addEventListener("error", errorHandler, false);
		ajax.addEventListener("load", completeHandler, false);
	var reg_id=parseInt(data.getAll("reg_id")[0]);
	if (! (reg_id >=4001 && reg_id <=4549)){
                if (! (reg_id>=5001 && reg_id <=5088)){
                        if (! (reg_id>=71001 && reg_id<=71017)){
                                if (! (reg_id>=71101 && reg_id<=71103)){
				$("#result").html('<h3 style="color:red;">Wrong Register Number</h6>');
                                }
		}
	}
}else{
	ajax.open("POST", url, true);
        ajax.send(data);
	}
        function progressHandler(event){
				console.log('progress')
				var percent = 100 *(event.loaded / event.total);
				$('.bar').css('width',percent+'%');
				console.log(percent);
    }


    function completeHandler(event){ 
      //alert("completed")
	  console.log(ajax.status);
	  if(ajax.status == 200){
	  $(".table-responsive").html(ajax.response)
	  }else{
	  $("#result").html('<h3 style="color:red;">Error in server</h6>');
	  }
	  delete ajax;
   }
   
   function errorHandler(event){
	$("#result").html('<h3 style="color:red;">Error in upload.Please Try again</h6>');
   }
			  
     } 
