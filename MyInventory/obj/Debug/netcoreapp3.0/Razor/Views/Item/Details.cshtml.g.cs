#pragma checksum "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\Item\Details.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "699048051eb2bf4996850d8e21e6381e857ce3be"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Item_Details), @"mvc.1.0.view", @"/Views/Item/Details.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\_ViewImports.cshtml"
using MyInventory;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\_ViewImports.cshtml"
using MyInventory.Models;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\_ViewImports.cshtml"
using MyInventory.ViewModels;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"699048051eb2bf4996850d8e21e6381e857ce3be", @"/Views/Item/Details.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"58cf24a99e6968f7c5011eecc4ad5dffaa0738f9", @"/Views/_ViewImports.cshtml")]
    public class Views_Item_Details : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<Item>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\n\n<h3>ID: ");
#nullable restore
#line 4 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\Item\Details.cshtml"
   Write(Model.Id);

#line default
#line hidden
#nullable disable
            WriteLiteral("</h3>\n<h3>Name: ");
#nullable restore
#line 5 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\Item\Details.cshtml"
     Write(Model.Name);

#line default
#line hidden
#nullable disable
            WriteLiteral("</h3>\n<h3>Category name: ");
#nullable restore
#line 6 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\Item\Details.cshtml"
              Write(Model.Category.CategoryName);

#line default
#line hidden
#nullable disable
            WriteLiteral("</h3>\n<h3>InStock: ");
#nullable restore
#line 7 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\Item\Details.cshtml"
        Write(Model.InStock);

#line default
#line hidden
#nullable disable
            WriteLiteral("</h3>\n<h3>Comment: ");
#nullable restore
#line 8 "C:\Dev\ASP.NETCore\Auth\MyInventory_advsept\MyInventory\Views\Item\Details.cshtml"
        Write(Model.Comment);

#line default
#line hidden
#nullable disable
            WriteLiteral("</h3>\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<Item> Html { get; private set; }
    }
}
#pragma warning restore 1591