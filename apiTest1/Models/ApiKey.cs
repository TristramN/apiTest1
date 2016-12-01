using System;
using System.ComponentModel.DataAnnotations;

namespace apiTest1.Models
{
    public class ApiKey
    {
        [Key]
        public virtual int Id { get; set; }
        public virtual Guid Key { get; set; }
        public virtual bool WriteAccess { get; set; }
        public virtual string Info { get; set; }
    }
}