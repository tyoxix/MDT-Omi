# App-Pakete für aktuellen Benutzer entfernen
$appxPackages = @(
    "Microsoft.3DBuilder",
    "Microsoft.AppConnector",
    "Microsoft.BingFinance",
    "Microsoft.BingNews",
    "Microsoft.BingSports",
    "Microsoft.BingTranslator",
    "Microsoft.BingWeather",
    "Microsoft.CommsPhone",
    "Microsoft.ConnectivityStore",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftPowerBIForWindows",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.MinecraftUWP",
    "Microsoft.MSPaint",
    "Microsoft.NetworkSpeedTest",
    "Microsoft.Office.OneNote",
    "Microsoft.Office.Sway",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.RemoteDesktop",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsPhone",
    "Microsoft.WindowsSoundRecorder",
    "2414FC7A.Viber",
    "41038Axilesoft.ACGMediaPlayer",
    "46928bounde.EclipseManager",
    "4DF9E0F8.Netflix",
    "64885BlueEdge.OneCalendar",
    "7EE7776C.LinkedInforWindows",
    "828B5831.HiddenCityMysteryofShadows",
    "89006A2E.AutodeskSketchBook",
    "9E2F88E3.Twitter",
    "A278AB0D.DisneyMagicKingdoms",
    "A278AB0D.MarchofEmpires",
    "ActiproSoftwareLLC.562882FEEB491",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "CAF9E577.Plex",
    "D52A8D61.FarmVille2CountryEscape",
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "DB6EA5DB.CyberLinkMediaSuiteEssentials",
    "DolbyLaboratories.DolbyAccess",
    "Drawboard.DrawboardPDF",
    "Facebook.Facebook",
    "flaregamesGmbH.RoyalRevolt2",
    "GAMELOFTSA.Asphalt8Airborne",
    "KeeperSecurityInc.Keeper",
    "king.com.BubbleWitch3Saga",
    "king.com.CandyCrushSodaSaga",
    "PandoraMediaInc.29680B314EFC2",
    "SpotifyAB.SpotifyMusic",
    "WinZipComputing.WinZipUniversal",
    "XINGAG.XING",
    "Microsoft.549981C3F5F10",
    "Microsoft.OutlookForWindows",
    "MicrosoftTeams",
    "Microsoft.Teams",
    "MSTeams",
    "Microsoft.Todos",
    "Microsoft.LinkedIn"
)

#Für bestehende Benutzer entfernen
foreach ($pkg in $appxPackages) {
    Get-AppxPackage -Name $pkg -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
}
#Für neue Benutzer (provisioned packages) entfernen
foreach ($pkg in $appxPackages) {
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $pkg | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

#Für Apps mit Wildcards
#Für bestehende Benutzer entfernen
Get-AppxPackage -AllUsers *solitairecollection* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers *WebExperience* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
#Für neue Benutzer entfernen (provisioned)
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*solitairecollection*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*WebExperience*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*xbox*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
