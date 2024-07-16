using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace APIWithJWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class BankingController : ControllerBase
    {
        [Authorize]
        [HttpGet("balance")]
        public IActionResult GetBalance()
        {
            // Aquí puedes obtener la información del balance del usuario desde la base de datos
            return Ok(new { balance = 1000 });
        }
    }
}
