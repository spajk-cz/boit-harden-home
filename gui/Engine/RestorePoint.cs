using System.Management;

namespace BoitHardenHome.Engine;

public static class RestorePoint
{
    /// <summary>Vytvori bod obnoveni systemu. Best-effort – pri neuspechu vrati false.</summary>
    public static bool Create(string description)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\default");
            var path = new ManagementPath("SystemRestore");
            using var cls = new ManagementClass(scope, path, null);
            using var inParams = cls.GetMethodParameters("CreateRestorePoint");
            inParams["Description"] = description;
            inParams["RestorePointType"] = 12; // MODIFY_SETTINGS
            inParams["EventType"] = 100;        // BEGIN_SYSTEM_CHANGE
            var result = cls.InvokeMethod("CreateRestorePoint", inParams, null);
            var rv = Convert.ToInt32(result["ReturnValue"]);
            return rv == 0;
        }
        catch
        {
            return false;
        }
    }
}
