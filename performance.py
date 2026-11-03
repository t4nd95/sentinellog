import streamlit as st


def render_performance():
    st.info("Yerel bilgisayardan performans aktarımı henüz bağlı değil.")
    st.write("**Yerel sürümde çalışan özellikler**")
    for feature in [
        "CPU, RAM ve disk ölçümleri ile geçmiş grafikleri",
        "Kayıtlı cihazların ping ve TCP erişilebilirlik kontrolleri",
        "Arka planda ölçüm ve CSV dışa aktarma",
    ]:
        st.write("• " + feature)
    st.caption(
        "Bu bulut sürümü bilgisayarınızın yerel ağına erişemez. "
        "Uzak toplayıcı bağlantısı eklendiğinde ölçümler burada gösterilecek. "
        "Bulut sunucusunun kaynakları bilgisayarınızın ölçümleri olarak gösterilmez."
    )
