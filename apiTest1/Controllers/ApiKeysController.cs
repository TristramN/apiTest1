using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Http;
using System.Web.Http.Description;
using apiTest1.Models;
using Jose;

namespace apiTest1.Controllers
{
    public class ApiKeysController : ApiController
    {
        private readonly ApiTestContext _db = new ApiTestContext();

        // GET: api/ApiKeys/5
        [ResponseType(typeof(string))]
        public IHttpActionResult GetApiKey(string guid)
        {
            if (guid != "701831de-cecb-49d6-b878-36a422d83eed")
            {
                return NotFound();
            }

            var token = Encode.EncodeToken("some-uid");

            return Ok(token);
        }


        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}